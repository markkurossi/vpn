//
// udp.go
//
// Copyright (c) 2019-2023 Markku Rossi
//
// All rights reserved.
//

package ip

import (
	"errors"
	"fmt"
)

const (
	// UDPHeaderLen defines the length of the UDP datagram header.
	UDPHeaderLen = 8
)

// UDP implements and UDP datagram.
type UDP struct {
	IP   Packet
	Src  uint16
	Dst  uint16
	Data []byte
}

// ParseUDP parses the UPD datagram.
func ParseUDP(ip Packet) (*UDP, error) {
	if ip.Protocol() != ProtoUDP {
		return nil, errors.New("Not UDP packet")
	}
	data := ip.Data()
	if len(data) < UDPHeaderLen {
		return nil, ErrorTruncated
	}
	//  0      7 8     15 16    23 24    31
	// +--------+--------+--------+--------+
	// |     Source      |   Destination   |
	// |      Port       |      Port       |
	// +--------+--------+--------+--------+
	// |                 |                 |
	// |     Length      |    Checksum     |
	// +--------+--------+--------+--------+
	// |
	// |          data octets ...
	// +---------------- ...

	length := bo.Uint16(data[4:])
	if length != uint16(len(data)) {
		fmt.Printf("Invalid length: header=%d, len=%d\n", length, len(data))
		return nil, ErrorInvalid
	}
	cks := bo.Uint16(data[6:])
	if cks != 0 {
		phdr := ip.PseudoHeader()
		phdr = append(phdr, data...)
		if len(phdr)%2 != 0 {
			phdr = append(phdr, 0)
		}
		if Checksum(phdr) != 0 {
			return nil, ErrorChecksum
		}
	}

	return &UDP{
		IP:   ip,
		Src:  bo.Uint16(data),
		Dst:  bo.Uint16(data[2:]),
		Data: data[UDPHeaderLen:],
	}, nil
}

// ParseUDPPacket parses the UDP packet.
func ParseUDPPacket(data []byte) (*UDP, error) {
	packet, err := Parse(data)
	if err != nil {
		return nil, err
	}
	switch packet.Protocol() {
	case ProtoUDP:
		return ParseUDP(packet)

	default:
		return nil, fmt.Errorf("Invalid protocol: %s", packet.Protocol())
	}
}

// Swap swaps the datagram source and destination addresses and ports.
func (udp *UDP) Swap() {
	udp.IP.Swap()
	udp.Src, udp.Dst = udp.Dst, udp.Src
}

// Marshal encodes the UDP datagram into binary data.
func (udp *UDP) Marshal() []byte {
	data := make([]byte, UDPHeaderLen+len(udp.Data))

	bo.PutUint16(data, udp.Src)
	bo.PutUint16(data[2:], udp.Dst)
	bo.PutUint16(data[4:], uint16(UDPHeaderLen+len(udp.Data)))
	copy(data[UDPHeaderLen:], udp.Data)

	udp.IP.SetData(data)

	// Compute checksum
	phdr := udp.IP.PseudoHeader()
	phdr = append(phdr, data...)
	if len(phdr)%2 != 0 {
		phdr = append(phdr, 0)
	}

	bo.PutUint16(data[6:], Checksum(phdr))

	return udp.IP.Marshal()
}
