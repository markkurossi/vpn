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
	"flag"
	"fmt"
	"log"
	"os"
	"os/signal"

	"github.com/markkurossi/vpn/cli"
	"github.com/markkurossi/vpn/dns"
	"github.com/markkurossi/vpn/ip"
	"github.com/markkurossi/vpn/tun"
)

func main() {
	bl := flag.String("blacklist", "", "DNS blacklist")
	doh := flag.String("doh", "", "DNS-over-HTTPS URL")
	interactive := flag.Bool("i", false, "Interactive mode")
	flag.Parse()

	var verbose int

	if *interactive {
		verbose = 0
	} else {
		verbose = 2
	}

	var blacklist []dns.Labels
	var err error

	if len(*bl) > 0 {
		blacklist, err = dns.ReadBlacklist(*bl)
		if err != nil {
			log.Fatal(err)
		}
		fmt.Printf("Blacklist: %v\n", bl)
	}

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
	proxy.Verbose = verbose
	proxy.Blacklist = blacklist

	if len(*doh) > 0 {
		doh, err := dns.NewDoHClient(*doh)
		if err != nil {
			log.Fatal(err)
		}
		proxy.DoH = doh
	}

	if *interactive {
		events := make(chan dns.Event)
		proxy.Events = events
		go cli.EventHandler(events)
	}

	origServers, err := dns.GetServers()
	if err != nil {
		log.Fatal(err)
	}
	fmt.Printf("Current DNS servers: %v\n", origServers)

	fmt.Printf("Setting proxy DNS server\n")
	err = dns.SetServers([]string{"192.168.192.254"})
	if err != nil {
		log.Fatalf("Failed to set proxy DNS: %s\n", err)
	}
	fmt.Printf("Flushing DNS cache\n")
	err = dns.FlushCache()
	if err != nil {
		log.Printf("Failed to flush DNS cache: %s\n", err)
	}

	c := make(chan os.Signal, 1)
	signal.Notify(c, os.Interrupt)

	go func() {
		s := <-c
		fmt.Println("signal", s)
		dns.SetServers(origServers)
		os.Exit(0)
	}()

	fmt.Printf("Processing DNS requests\n")
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
				if d.Query() {
					go func() {
						err := proxy.Query(udp, d)
						if err != nil {
							fmt.Printf("DNS client write failed: %s\n", err)
						}
					}()
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
