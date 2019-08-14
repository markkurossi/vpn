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

const (
	HeaderLen = 12
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

type ID uint16

func (d *DNS) Query() bool {
	return !d.QR
}

func (d *DNS) Dump() {
	var qr string
	if d.QR {
		qr = "response"
	} else {
		qr = "query"
	}
	fmt.Printf("DNS %04x: %s %s AA=%v TC=%v RD=%v RA=%v (%s)\n",
		d.ID, qr, d.Opcode, d.AA, d.TC, d.RD, d.RA, d.RCODE)
	for _, q := range d.Questions {
		fmt.Printf("  Q: %s QTYPE=%04x, QCLASS=%04x\n",
			q.Labels, q.QTYPE, q.QCLASS)
	}
	for _, r := range d.Answers {
		r.Dump(" AN")
	}
	for _, r := range d.Authority {
		r.Dump(" NS")
	}
	for _, r := range d.Additional {
		r.Dump(" AR")
	}
}

type Labels []string

func (l Labels) String() string {
	return strings.Join(l, ".")
}

type Question struct {
	Labels Labels
	QTYPE  uint16
	QCLASS uint16
}

type Record struct {
	Labels Labels
	TYPE   uint16
	CLASS  uint16
	TTL    TTL
	RDATA  []byte
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

func (r *Record) Dump(prefix string) {
	fmt.Printf("%s: %s TYPE=%04x CLASS=%04x TTL=%s",
		prefix, r.Labels, r.TYPE, r.CLASS, r.TTL)
	if len(r.RDATA) == 0 {
		fmt.Printf("\n")
	} else {
		fmt.Printf(" RDATA:\n%s", hex.Dump(r.RDATA))
	}
}

type Opcode uint8

const (
	QUERY Opcode = iota
	IQUERY
	STATUS
)

func (oc Opcode) String() string {
	switch oc {
	case QUERY:
		return "QUERY"
	case IQUERY:
		return "IQUERY"
	case STATUS:
		return "STATUS"
	default:
		return fmt.Sprintf("{Opcode %d}", oc)
	}
}

type RCODE uint8

const (
	NoError RCODE = iota
	FormErr
	ServFail
	NXDomain
	NotImp
	Refused
	YXDomain
	YXRRSet
	NXRRSet
	NotAuth
	NotZone
	BADVERS
	BADSIG
	BADKEY
	BADTIME
	BADMODE
	BADNAME
	BADALG
)

var rcodes = map[RCODE]string{
	NoError:  "No Error",
	FormErr:  "Format Error",
	ServFail: "Server Failure",
	NXDomain: "Non-Existent Domain",
	NotImp:   "Not Implemented",
	Refused:  "Query Refused",
	YXDomain: "Name Exists when it should not",
	YXRRSet:  "RR Set Exists when it should not",
	NXRRSet:  "RR Set that should exist does not",
	NotAuth:  "Server Not Authoritative for zone",
	NotZone:  "Name not contained in zone",
	BADVERS:  "Bad OPT Version",
	BADSIG:   "TSIG Signature Failure",
	BADKEY:   "Key not recognized",
	BADTIME:  "Signature out of time window",
	BADMODE:  "Bad TKEY Mode",
	BADNAME:  "Duplicate key name",
	BADALG:   "Algorithm not supported",
}

func (rc RCODE) String() string {
	val, ok := rcodes[rc]
	if ok {
		return val
	}
	return fmt.Sprintf("{RCODE %d}", rc)
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
		QR:     (flags>>15)&0x1 == 1,
		Opcode: Opcode((flags >> 11) & 0xf),
		AA:     (flags>>10)&0x1 == 1,
		TC:     (flags>>9)&0x1 == 1,
		RD:     (flags>>8)&0x1 == 1,
		RA:     (flags>>7)&0x1 == 1,
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
	q.QTYPE = bo.Uint16(data[ofs:])
	q.QCLASS = bo.Uint16(data[ofs+2:])
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
	r.TYPE = bo.Uint16(data[ofs:])
	r.CLASS = bo.Uint16(data[ofs+2:])
	r.TTL = TTL(bo.Uint32(data[ofs+4:]))

	rdlength := int(bo.Uint16(data[ofs+8:]))
	ofs += 10

	if ofs+rdlength > len(data) {
		return nil, ofs, ip.ErrorTruncated
	}
	r.RDATA = data[ofs : ofs+rdlength]
	ofs += rdlength

	return r, ofs, nil
}

func parseLabels(data []byte, ofs int, allowPtr bool) ([]string, int, error) {
	var labels []string

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
