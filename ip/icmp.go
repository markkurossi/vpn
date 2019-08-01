//
// icmp.go
//
// Copyright (c) 2019 Markku Rossi
//
// All rights reserved.
//

package ip

import (
	"errors"
)

type ICMPType uint8

var icmpTypes = map[ICMPType]string{
	0:  "Echo Reply",
	3:  "Destination Unreachable",
	4:  "Source Quench",
	5:  "Redirect",
	8:  "Echo",
	11: "Time Exceeded",
	12: "Parameter Problem",
	13: "Timestamp",
	14: "Timestamp Reply",
	15: "Information Request",
	16: "Information Reply",
}

func ICMPResponse(packet Packet) (Packet, error) {
	if packet.Protocol() != ProtoICMP {
		return nil, errors.New("Not ICMP packet")
	}
	data := packet.Data()
	if len(data) < 1 {
		return nil, ErrorTruncated
	}
	icmpType := ICMPType(data[0])
	switch icmpType {
	// Echo request
	case 8:
		//  0                   1                   2                   3
		//  0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1
		// +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
		// |     Type      |     Code      |          Checksum             |
		// +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
		// |           Identifier          |        Sequence Number        |
		// +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
		// |     Data ...
		// +-+-+-+-+-
		if len(data) < 8 {
			return nil, ErrorTruncated
		}
		// Set type to Echo Reply
		data[0] = 0

		// Compute checksum
		bo.PutUint16(data[2:], 0)
		chk := Checksum(data)
		bo.PutUint16(data[2:], chk)

		response := packet.Copy()
		response.SetSrc(packet.Dst())
		response.SetDst(packet.Src())
		response.SetData(data)

		return response, nil
	}

	return nil, nil
}
