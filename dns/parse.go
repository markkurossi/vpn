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
	ID        uint16
	QR        bool
	Opcode    Opcode
	AA        bool
	TC        bool
	RD        bool
	RA        bool
	RCODE     RCODE
	Questions []*Question
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
			strings.Join(q.Labels, "."), q.QTYPE, q.QCLASS)
	}
}

type Question struct {
	Labels []string
	QTYPE  uint16
	QCLASS uint16
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
	FormatError
	ServerFailure
	NameError
	NotImplemented
	Refused
)

var rcodes = map[RCODE]string{
	NoError:        "NoError",
	FormatError:    "FormatError",
	ServerFailure:  "ServerFailure",
	NameError:      "NameError",
	NotImplemented: "NotImplemented",
	Refused:        "Refused",
}

func (rc RCODE) String() string {
	val, ok := rcodes[rc]
	if ok {
		return val
	}
	return fmt.Sprintf("{RCODE %d}", rc)
}

func Parse(packet *ip.UDP) (*DNS, error) {
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
	if len(packet.Data) < 12 {
		return nil, ip.ErrorTruncated
	}
	flags := bo.Uint16(packet.Data[2:])
	dns := &DNS{
		ID:     bo.Uint16(packet.Data),
		QR:     flags&0x1 == 1,
		Opcode: Opcode((flags >> 1) & 0xf),
		AA:     (flags>>5)&0x1 == 1,
		TC:     (flags>>6)&0x1 == 1,
		RD:     (flags>>7)&0x1 == 1,
		RA:     (flags>>8)&0x1 == 1,
		RCODE:  RCODE((flags >> 12) & 0xf),
	}
	qdcount := int(bo.Uint16(packet.Data[4:]))
	//ancount := bo.Uint16(packet.Data[6:])
	//nscount := bo.Uint16(packet.Data[8:])
	//arcount := bo.Uint16(packet.Data[10:])

	ofs := 12
	for i := 0; i < qdcount; i++ {
		var q *Question
		var err error
		q, ofs, err = parseQuestion(packet.Data, ofs)
		if err != nil {
			return nil, err
		}
		fmt.Printf("Question: %+v\n", q)
		dns.Questions = append(dns.Questions, q)
	}

	fmt.Printf("Rest:\n%s", hex.Dump(packet.Data[ofs:]))

	return dns, nil
}

func parseQuestion(data []byte, ofs int) (*Question, int, error) {
	q := new(Question)

	// Parse labels
	for ofs < len(data) {
		l := int(data[ofs])
		ofs++

		if ofs+l > len(data) {
			return nil, 0, ip.ErrorTruncated
		}
		if l == 0 {
			break
		}
		q.Labels = append(q.Labels, string(data[ofs:ofs+l]))
		ofs += l
	}
	if ofs+4 > len(data) {
		return nil, 0, ip.ErrorTruncated
	}
	q.QTYPE = bo.Uint16(data[ofs:])
	q.QCLASS = bo.Uint16(data[ofs+2:])
	ofs += 4

	return q, ofs, nil
}
