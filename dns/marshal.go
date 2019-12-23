//
// marshal.go
//
// Copyright (c) 2019 Markku Rossi
//
// All rights reserved.
//

package dns

import (
	"bytes"
	"fmt"
)

func (dns *DNS) Marshal() ([]byte, error) {
	data := make([]byte, HeaderLen)
	bo.PutUint16(data, uint16(dns.ID))

	var flags uint16

	if dns.QR {
		flags |= FlagQR
	}
	flags |= uint16(dns.Opcode) << 11
	if dns.AA {
		flags |= FlagAA
	}
	if dns.TC {
		flags |= FlagTC
	}
	if dns.RD {
		flags |= FlagRD
	}
	if dns.RA {
		flags |= FlagRA
	}
	flags |= uint16(dns.RCODE)

	bo.PutUint16(data[2:], flags)
	bo.PutUint16(data[4:], uint16(len(dns.Questions)))
	bo.PutUint16(data[6:], uint16(len(dns.Answers)))
	bo.PutUint16(data[8:], uint16(len(dns.Authority)))
	bo.PutUint16(data[10:], uint16(len(dns.Additional)))

	for _, q := range dns.Questions {
		d, err := q.Marshal()
		if err != nil {
			return nil, err
		}
		data = append(data, d...)
	}
	for _, r := range dns.Answers {
		d, err := r.Marshal()
		if err != nil {
			return nil, err
		}
		data = append(data, d...)
	}
	for _, r := range dns.Authority {
		d, err := r.Marshal()
		if err != nil {
			return nil, err
		}
		data = append(data, d...)
	}
	for _, r := range dns.Additional {
		d, err := r.Marshal()
		if err != nil {
			return nil, err
		}
		data = append(data, d...)
	}

	return data, nil
}

func (q *Question) Marshal() ([]byte, error) {
	buf := new(bytes.Buffer)

	err := marshalLabels(buf, q.Labels)
	if err != nil {
		return nil, err
	}

	var tmp [2]byte
	bo.PutUint16(tmp[:], uint16(q.QTYPE))
	buf.Write(tmp[:])
	bo.PutUint16(tmp[:], uint16(q.QCLASS))
	buf.Write(tmp[:])

	return buf.Bytes(), nil
}

func marshalLabels(buf *bytes.Buffer, labels Labels) error {
	for _, label := range labels {
		bytes := []byte(label)
		if len(bytes) > 127 {
			return fmt.Errorf("Too long label")
		}
		buf.WriteByte(byte(len(bytes)))
		buf.Write(bytes)
	}
	// Labels are terminated with an empty element.
	buf.WriteByte(0)

	return nil
}

func (r *Record) Marshal() ([]byte, error) {
	buf := new(bytes.Buffer)

	marshalLabels(buf, r.Labels)

	var tmp [4]byte
	bo.PutUint16(tmp[:], uint16(r.TYPE))
	buf.Write(tmp[0:2])
	bo.PutUint16(tmp[:], uint16(r.CLASS))
	buf.Write(tmp[0:2])
	bo.PutUint32(tmp[:], uint32(r.TTL))
	buf.Write(tmp[0:4])

	bo.PutUint16(tmp[:], uint16(r.RDATA.Len()))
	buf.Write(tmp[0:2])

	buf.Write(r.RDATA.Bytes())

	return buf.Bytes(), nil
}
