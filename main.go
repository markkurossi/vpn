//
// main.go
//
// Copyright (c) 2019 Markku Rossi
//
// All rights reserved.
//

package main

import (
	"encoding/hex"
	"fmt"
	"log"

	"github.com/markkurossi/vpn/ip"
	"github.com/markkurossi/vpn/tun"
)

func main() {
	tunnel, err := tun.Create()
	if err != nil {
		log.Fatal(err)
	}
	fmt.Printf("Tunnel: %s\n", tunnel)
	err = tunnel.Configure()
	if err != nil {
		log.Fatal(err)
	}

	for {
		data, err := tunnel.Read()
		if err != nil {
			log.Fatal(err)
		}
		packet, err := ip.Parse(data)
		if err != nil {
			fmt.Printf("%s: packet:\n%s", err, hex.Dump(data))
			continue
		}
		switch packet.Protocol() {
		case ip.ProtoICMP:
			response, err := ip.ICMPResponse(packet)
			if err != nil {
				fmt.Printf("Failed to create ICMP response: %v\n", err)
			} else if response != nil {
				err = tunnel.Write(response.Marshal())
			}
		default:
			fmt.Printf("Packet: %s\n%s", packet, hex.Dump(packet.Data()))
		}
	}
}
