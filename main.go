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

	"github.com/markkurossi/vpn/dns"
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

	proxy, err := dns.NewProxy("8.8.8.8:53", "192.168.192.254:55", tunnel)
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
				_, err = tunnel.Write(response.Marshal())
			}

		case ip.ProtoUDP:
			udp, err := ip.ParseUDP(packet)
			if err != nil {
				fmt.Printf("Failed to parse UDP packet: %v\n", err)
				continue
			}
			switch udp.Dst {
			case 53:
				d, err := dns.Parse(udp.Data)
				if err != nil {
					fmt.Printf("Failed to parse DNS packet: %v\n", err)
					continue
				}
				// d.Dump()
				if d.Query() {
					err := proxy.Query(udp, udp.Data, d)
					if err != nil {
						fmt.Printf("DNS client write failed: %s\n", err)
					}
				}

			default:
				fmt.Printf("UDP %d->%d\n%s", udp.Src, udp.Dst,
					hex.Dump(udp.Data))
			}

		default:
			fmt.Printf("Packet: %s\n%s", packet, hex.Dump(packet.Data()))
		}
	}
}
