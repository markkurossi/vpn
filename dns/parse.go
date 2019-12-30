//
// parse.go
//
// Copyright (c) 2019 Markku Rossi
//
// All rights reserved.
//

package dns

import (
	"encoding/binary"
	"encoding/hex"
	"fmt"
	"strings"

	"github.com/markkurossi/vpn/ip"
)

var (
	bo = binary.BigEndian
)

type DNS struct {
	ID         ID
	QR         bool
	Opcode     Opcode
	AA         bool
	TC         bool
	RD         bool
	RA         bool
	RCODE      RCODE
	Questions  []*Question
	Answers    []*Record
	Authority  []*Record
	Additional []*Record
}

func (d *DNS) Query() bool {
	return !d.QR
}

// GetAdditional gets the additional record of the specified type. The
// function returns nil if the additional record is not found.
func (d *DNS) GetAdditional(t TYPE) *Record {
	for _, r := range d.Additional {
		if r.TYPE == t {
			return r
		}
	}
	return nil
}

func (d *DNS) Dump() {
	var qr string
	if d.QR {
		qr = "response"
	} else {
		qr = "query"
	}
	fmt.Printf("DNS %s: %s %s AA=%v TC=%v RD=%v RA=%v (%s)\n",
		d.ID, qr, d.Opcode, d.AA, d.TC, d.RD, d.RA, d.RCODE)
	for _, q := range d.Questions {
		fmt.Printf("    Q: %s QTYPE=%s, QCLASS=%s\n",
			q.Labels, q.QTYPE, q.QCLASS)
	}
	for _, r := range d.Answers {
		r.Dump("  Ans")
	}
	for _, r := range d.Authority {
		r.Dump(" Auth")
	}
	for _, r := range d.Additional {
		r.Dump("  Add")
	}
}

type Labels []string

func NewLabels(name string) Labels {
	return strings.Split(name, ".")
}

func (l Labels) String() string {
	return strings.Join(l, ".")
}

func (l Labels) Match(o Labels) bool {
	return glob(l, o)
}

func glob(value, pattern []string) bool {
	for {
		if len(pattern) == 0 {
			if len(value) == 0 {
				return true
			}
			return false
		} else if len(value) == 0 {
			return false
		}
		switch pattern[0] {
		case "*":
			for i := 1; i <= len(value); i++ {
				if glob(value[i:], pattern[1:]) {
					return true
				}
			}
			return false

		case "**":
			for i := 0; i <= len(value); i++ {
				if glob(value[i:], pattern[1:]) {
					return true
				}
			}
			return false

		default:
			if pattern[0] != value[0] {
				return false
			}
		}
		pattern = pattern[1:]
		value = value[1:]
	}
}

type Question struct {
	Labels Labels
	QTYPE  TYPE
	QCLASS CLASS
}

type Record struct {
	Labels Labels
	TYPE   TYPE
	CLASS  CLASS
	TTL    TTL
	RDATA  RDATA
}

type RDATA struct {
	Data  []byte
	Start int
	End   int
}

func (r RDATA) Len() int {
	return r.End - r.Start
}

func (r RDATA) Bytes() []byte {
	return r.Data[r.Start:r.End]
}

type TTL uint32

func (ttl TTL) String() string {
	if ttl <= 60 {
		return fmt.Sprintf("%ds", ttl)
	} else if ttl <= 60*60 {
		minutes := ttl / 60
		seconds := ttl % 60
		return fmt.Sprintf("%dm%ds", minutes, seconds)
	} else {
		hours := ttl / 3600
		minutes := (ttl % 3600) / 60
		seconds := (ttl % 3600) % 60
		return fmt.Sprintf("%dh%dm%ds", hours, minutes, seconds)
	}
}

func space(prefix string) string {
	var result string

	for i := 0; i < len(prefix); i++ {
		result += " "
	}
	return result
}

func (r *Record) Dump(prefix string) {
	fmt.Printf("%s: %s TYPE=%s CLASS=%s TTL=%s\n",
		prefix, r.Labels, r.TYPE, r.CLASS, r.TTL)
	if r.RDATA.Len() == 0 {
		return
	}
	switch r.TYPE {
	case A:
		if r.RDATA.Len() == 4 {
			data := r.RDATA.Bytes()
			fmt.Printf("%s  %s=%d.%d.%d.%d\n",
				space(prefix), r.TYPE, data[0], data[1], data[2], data[3])
		}

	case CNAME:
		labels, ofs, err := parseLabels(r.RDATA.Data, r.RDATA.Start, true)
		if err != nil || ofs != r.RDATA.End {
			fmt.Printf("Malformed CNAME:\n%s", hex.Dump(r.RDATA.Bytes()))
			return
		}
		fmt.Printf("%s  %s=%s\n", space(prefix), r.TYPE, labels)

	case SOA:
		mname, ofs, err := parseLabels(r.RDATA.Data, r.RDATA.Start, true)
		if err != nil {
			fmt.Printf("Malformed MNAME:\n%s", hex.Dump(r.RDATA.Bytes()))
			return
		}
		rname, ofs, err := parseLabels(r.RDATA.Data, ofs, true)
		if err != nil {
			fmt.Printf("Malformed RNAME:\n%s", hex.Dump(r.RDATA.Bytes()))
			return
		}
		if r.RDATA.End-ofs != 20 {
			fmt.Printf("Malformed SOA:\n%s", hex.Dump(r.RDATA.Bytes()))
		}
		serial := bo.Uint32(r.RDATA.Data[ofs:])
		refresh := bo.Uint32(r.RDATA.Data[ofs+4:])
		retry := bo.Uint32(r.RDATA.Data[ofs+8:])
		expire := bo.Uint32(r.RDATA.Data[ofs+12:])
		minimum := bo.Uint32(r.RDATA.Data[ofs+16:])

		fmt.Printf("%s  %s: MNAME=%s RNAME=%s SERIAL=%d REFRESH=%d RETRY=%d EXPIRE=%d MINIMUM=%d\n",
			space(prefix), r.TYPE, mname, rname, serial, refresh, retry,
			expire, minimum)

	case OPT:
		data := r.RDATA.Bytes()
		for len(data) > 0 {
			if len(data) < 4 {
				fmt.Printf("Truncated option:\n%s", hex.Dump(data))
				break
			}
			code := OptCode(bo.Uint16(data))
			length := int(bo.Uint16(data[2:]))
			data = data[4:]
			if length > len(data) {
				fmt.Printf("Truncated option %s: length=%d\n%s",
					code, length, hex.Dump(data))
				break
			}
			fmt.Printf("%s  %s:\n%s", space(prefix), code,
				hex.Dump(data[:length]))
			data = data[length:]
		}

	default:
		fmt.Printf("%s  %s:\n%s", space(prefix), r.TYPE,
			hex.Dump(r.RDATA.Bytes()))
	}
}

func (r *Record) HasOpt(code OptCode) []byte {
	if r.TYPE != OPT {
		return nil
	}
	data := r.RDATA.Bytes()
	for len(data) > 0 {
		if len(data) < 4 {
			return nil
		}
		c := OptCode(bo.Uint16(data))
		l := int(bo.Uint16(data[2:]))
		data = data[4:]
		if l > len(data) {
			return nil
		}
		if c == code {
			return data[:l]
		}
		data = data[l:]
	}
	return nil
}

func Parse(packet []byte) (*DNS, error) {
	//                                 1  1  1  1  1  1
	//   0  1  2  3  4  5  6  7  8  9  0  1  2  3  4  5
	// +--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+
	// |                      ID                       |
	// +--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+
	// |QR|   Opcode  |AA|TC|RD|RA|   Z    |   RCODE   |
	// +--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+
	// |                    QDCOUNT                    |
	// +--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+
	// |                    ANCOUNT                    |
	// +--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+
	// |                    NSCOUNT                    |
	// +--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+
	// |                    ARCOUNT                    |
	// +--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+
	if len(packet) < HeaderLen {
		return nil, ip.ErrorTruncated
	}
	flags := bo.Uint16(packet[2:])
	dns := &DNS{
		ID:     ID(bo.Uint16(packet)),
		QR:     flags&FlagQR == FlagQR,
		Opcode: Opcode((flags >> 11) & 0xf),
		AA:     flags&FlagAA == FlagAA,
		TC:     flags&FlagTC == FlagTC,
		RD:     flags&FlagRD == FlagRD,
		RA:     flags&FlagRA == FlagRA,
		RCODE:  RCODE(flags & 0xf),
	}
	qdcount := int(bo.Uint16(packet[4:]))
	ancount := int(bo.Uint16(packet[6:]))
	nscount := int(bo.Uint16(packet[8:]))
	arcount := int(bo.Uint16(packet[10:]))

	ofs := HeaderLen
	for i := 0; i < qdcount; i++ {
		var q *Question
		var err error
		q, ofs, err = parseQuestion(packet, ofs)
		if err != nil {
			return nil, err
		}
		dns.Questions = append(dns.Questions, q)
	}
	for i := 0; i < ancount; i++ {
		var r *Record
		var err error
		r, ofs, err = parseRecord(packet, ofs)
		if err != nil {
			return nil, err
		}
		dns.Answers = append(dns.Answers, r)
	}
	for i := 0; i < nscount; i++ {
		var r *Record
		var err error
		r, ofs, err = parseRecord(packet, ofs)
		if err != nil {
			return nil, err
		}
		dns.Authority = append(dns.Authority, r)
	}
	for i := 0; i < arcount; i++ {
		var r *Record
		var err error
		r, ofs, err = parseRecord(packet, ofs)
		if err != nil {
			return nil, err
		}
		dns.Additional = append(dns.Additional, r)
	}

	if ofs < len(packet) {
		fmt.Printf("Trailing data:\n%s", hex.Dump(packet[ofs:]))
	}

	return dns, nil
}

func parseQuestion(data []byte, ofs int) (*Question, int, error) {
	q := new(Question)

	var labels []string
	var err error

	labels, ofs, err = parseLabels(data, ofs, false)
	if err != nil {
		return nil, ofs, err
	}
	if ofs+4 > len(data) {
		return nil, 0, ip.ErrorTruncated
	}
	q.Labels = labels
	q.QTYPE = TYPE(bo.Uint16(data[ofs:]))
	q.QCLASS = CLASS(bo.Uint16(data[ofs+2:]))
	ofs += 4

	return q, ofs, nil
}

func parseRecord(data []byte, ofs int) (*Record, int, error) {
	//                                 1  1  1  1  1  1
	//   0  1  2  3  4  5  6  7  8  9  0  1  2  3  4  5
	// +--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+
	// |                                               |
	// /                                               /
	// /                      NAME                     /
	// |                                               |
	// +--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+
	// |                      TYPE                     |
	// +--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+
	// |                     CLASS                     |
	// +--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+
	// |                      TTL                      |
	// |                                               |
	// +--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+
	// |                   RDLENGTH                    |
	// +--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--|
	// /                     RDATA                     /
	// /                                               /
	// +--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+

	r := new(Record)

	var labels []string
	var err error

	labels, ofs, err = parseLabels(data, ofs, true)
	if err != nil {
		return nil, ofs, err
	}
	if ofs+10 > len(data) {
		return nil, ofs, ip.ErrorTruncated
	}
	r.Labels = labels
	r.TYPE = TYPE(bo.Uint16(data[ofs:]))
	r.CLASS = CLASS(bo.Uint16(data[ofs+2:]))
	r.TTL = TTL(bo.Uint32(data[ofs+4:]))

	rdlength := int(bo.Uint16(data[ofs+8:]))
	ofs += 10

	if ofs+rdlength > len(data) {
		return nil, ofs, ip.ErrorTruncated
	}
	r.RDATA = RDATA{
		Data:  data,
		Start: ofs,
		End:   ofs + rdlength,
	}
	ofs += rdlength

	return r, ofs, nil
}

func parseLabels(data []byte, ofs int, allowPtr bool) (Labels, int, error) {
	var labels Labels

	for ofs < len(data) {
		if data[ofs]&0xc0 == 0xc0 {
			// Pointer.
			if !allowPtr {
				return nil, ofs, ip.ErrorInvalid
			}
			if ofs+1 >= len(data) {
				return nil, ofs, ip.ErrorTruncated
			}
			offset := int(bo.Uint16(data[ofs:]))
			ofs += 2

			offset &= 0x3fff
			if offset == ofs-2 {
				// Pointer to the pointer itself.
				return nil, ofs, ip.ErrorInvalid
			}
			pl, _, err := parseLabels(data, offset, true)
			if err != nil {
				return nil, ofs, err
			}

			labels = append(labels, pl...)
			return labels, ofs, nil
		}

		l := int(data[ofs])
		ofs++

		if ofs+l > len(data) {
			return nil, ofs, ip.ErrorTruncated
		}
		if l == 0 {
			return labels, ofs, nil
		}
		labels = append(labels, string(data[ofs:ofs+l]))
		ofs += l
	}

	return nil, ofs, ip.ErrorTruncated
}
