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
	"errors"
	"fmt"
	"net"
)

var (
	bo = binary.BigEndian
)

func ParseIPv4(data []byte) (Packet, error) {
	if len(data) < 20 {
		return nil, errors.New("Truncated packet")
	}
	ihl := data[0] & 0x0f
	length := bo.Uint16(data[2:])

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
		data:     data[ihl*4 : length],
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

func (p *IPv4) Dst() net.IP {
	return p.dst
}

func (p *IPv4) Data() []byte {
	return p.data
}
