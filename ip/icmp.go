//
// icmp.go
//
// Copyright (c) 2019-2024 Markku Rossi
//
// All rights reserved.
//

package ip

import (
	"errors"

	"github.com/gopacket/gopacket"
	"github.com/gopacket/gopacket/layers"
)

// ICMPv4Response creates an ICMPv4 response packet.
func ICMPv4Response(packet gopacket.Packet, icmp *layers.ICMPv4) (
	[]byte, error) {

	var payload gopacket.Payload
	var response layers.ICMPv4

	switch icmp.TypeCode.Type() {
	case layers.ICMPv4TypeEchoRequest:
		response = *icmp
		response.TypeCode = layers.CreateICMPv4TypeCode(
			layers.ICMPv4TypeEchoReply, icmp.TypeCode.Code())
		payload = icmp.LayerPayload()

	default:
		return nil, nil
	}

	// Response IP header.
	layer := packet.Layer(layers.LayerTypeIPv4)
	if layer == nil {
		return nil, errors.New("non-IPv4 packet for ICMPv4")
	}
	ip, _ := layer.(*layers.IPv4)
	ipLayer := *ip
	ipLayer.SrcIP = ip.DstIP
	ipLayer.DstIP = ip.SrcIP

	buffer := gopacket.NewSerializeBuffer()
	err := gopacket.SerializeLayers(buffer, gopacket.SerializeOptions{
		FixLengths:       false,
		ComputeChecksums: true,
	}, &ipLayer, &response, payload)
	if err != nil {
		return nil, err
	}

	return buffer.Bytes(), nil
}
