//
// v4.go
//
// Copyright (c) 2019 Markku Rossi
//
// All rights reserved.
//

package ip

import (
	"encoding/binary"
	"fmt"
	"net"
)

var (
	bo = binary.BigEndian
)

func ParseIPv4(data []byte) (Packet, error) {
	if len(data) < 20 {
		return nil, ErrorTruncated
	}
	ihl := int(data[0] & 0x0f)
	headerLen := ihl * 4
	length := int(bo.Uint16(data[2:]))

	if headerLen < 20 || headerLen > length {
		return nil, ErrorInvalid
	}
	if length > len(data) {
		return nil, ErrorTruncated
	}
	if Checksum(data[0:headerLen]) != 0 {
		return nil, ErrorChecksum
	}

	return &IPv4{
		version:  int(data[0] >> 4),
		tos:      int(data[1]),
		id:       bo.Uint16(data[4:]),
		flags:    int8(data[6] >> 5),
		offset:   bo.Uint16(data[6:]) & 0x1fff,
		ttl:      data[8],
		protocol: Protocol(data[9]),
		src:      net.IP(data[12:16]),
		dst:      net.IP(data[16:20]),
		data:     data[headerLen:length],
	}, nil
}

type IPv4 struct {
	version  int
	tos      int
	id       uint16
	flags    int8
	offset   uint16
	ttl      uint8
	protocol Protocol
	src      net.IP
	dst      net.IP
	data     []byte
}

func (p *IPv4) String() string {
	return fmt.Sprintf("IPv4 %s %s->%s", p.protocol, p.src, p.dst)
}

func (p *IPv4) Copy() Packet {
	var packet IPv4

	packet = *p

	// Take copy of the data
	data := make([]byte, len(p.data))
	copy(data, p.data)
	packet.data = data

	return &packet
}

func (p *IPv4) Swap() {
	p.src, p.dst = p.dst, p.src
}

func (p *IPv4) Marshal() []byte {
	data := make([]byte, 20+len(p.data))

	//  0                   1                   2                   3
	//  0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1
	// +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
	// |Version|  IHL  |Type of Service|          Total Length         |
	// +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
	// |         Identification        |Flags|      Fragment Offset    |
	// +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
	// |  Time to Live |    Protocol   |         Header Checksum       |
	// +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
	// |                       Source Address                          |
	// +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
	// |                    Destination Address                        |
	// +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
	// |                    Options                    |    Padding    |
	// +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+

	data[0] = byte(p.version<<4 | 5)
	data[1] = byte(p.tos)
	bo.PutUint16(data[2:], uint16(len(data)))
	bo.PutUint16(data[4:], p.id)
	bo.PutUint16(data[6:], (uint16(p.flags)<<13)|(p.offset&0x1fff))
	data[8] = p.ttl
	data[9] = byte(p.protocol)
	copy(data[12:], p.src[0:4])
	copy(data[16:], p.dst[0:4])
	copy(data[20:], p.data)

	cks := Checksum(data[0:20])
	bo.PutUint16(data[10:], cks)

	return data
}

func (p *IPv4) PseudoHeader() []byte {
	data := make([]byte, 12)
	copy(data, p.src)
	copy(data[4:], p.dst)
	data[9] = byte(p.protocol)

	bo.PutUint16(data[10:], uint16(len(p.data)))

	return data
}

func (p *IPv4) Version() int {
	return p.version
}

func (p *IPv4) TOS() int {
	return p.tos
}

func (p *IPv4) ID() uint16 {
	return p.id
}

func (p *IPv4) Flags() int8 {
	return p.flags
}

func (p *IPv4) Offset() uint16 {
	return p.offset
}

func (p *IPv4) TTL() uint8 {
	return p.ttl
}

func (p *IPv4) Protocol() Protocol {
	return p.protocol
}

func (p *IPv4) Src() net.IP {
	return p.src
}

func (p *IPv4) SetSrc(src net.IP) {
	p.src = src
}

func (p *IPv4) Dst() net.IP {
	return p.dst
}

func (p *IPv4) SetDst(dst net.IP) {
	p.dst = dst
}

func (p *IPv4) Data() []byte {
	return p.data
}

func (p *IPv4) SetData(data []byte) {
	p.data = data
}
