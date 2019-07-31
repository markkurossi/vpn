//
// icmp.go
//
// Copyright (c) 2019 Markku Rossi
//
// All rights reserved.
//

package ip

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

type ICMP struct {
	Packet Packet
	Type   ICMPType
}
