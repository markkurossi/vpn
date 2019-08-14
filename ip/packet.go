//
// packet.go
//
// Copyright (c) 2019 Markku Rossi
//
// All rights reserved.
//

package ip

import (
	"errors"
	"fmt"
	"net"
)

type Packet interface {
	Copy() Packet

	// Swap swaps source and destination IP addresses.
	Swap()
	Marshal() []byte
	PseudoHeader() []byte
	Version() int
	TOS() int
	ID() uint16
	Flags() int8
	Offset() uint16
	TTL() uint8
	Protocol() Protocol
	Src() net.IP
	SetSrc(src net.IP)
	Dst() net.IP
	SetDst(dst net.IP)
	Data() []byte
	SetData(data []byte)
}

func Parse(data []byte) (Packet, error) {
	if len(data) < 20 {
		return nil, errors.New("Truncated packet")
	}
	version := data[0] >> 4
	switch version {
	case 4:
		return ParseIPv4(data)
	default:
		return nil, fmt.Errorf("IPv%d not supported yet", version)
	}
}
