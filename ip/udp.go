//
// udp.go
//
// Copyright (c) 2019 Markku Rossi
//
// All rights reserved.
//

package ip

import (
	"errors"
)

type UDP struct {
	IP   Packet
	Src  uint16
	Dst  uint16
	Data []byte
}

func ParseUDP(ip Packet) (*UDP, error) {
	if ip.Protocol() != ProtoUDP {
		return nil, errors.New("Not UDP packet")
	}
	data := ip.Data()
	if len(data) < 8 {
		return nil, errorTruncated
	}
	length := bo.Uint16(data[4:])
	if length != uint16(len(data)) {
		return nil, errorInvalid
	}
	cks := bo.Uint16(data[6:])
	if cks != 0 {
		phdr := ip.PseudoHeader()
		phdr = append(phdr, data...)
		if len(phdr)%2 != 0 {
			phdr = append(phdr, 0)
		}
		if Checksum(phdr) != 0 {
			return nil, errorChecksum
		}
	}

	return &UDP{
		IP:   ip,
		Src:  bo.Uint16(data),
		Dst:  bo.Uint16(data[2:]),
		Data: data[8:],
	}, nil
}
