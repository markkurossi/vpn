//
// main.go
//
// Copyright (c) 2019-2021 Markku Rossi
//
// All rights reserved.
//

package main

import (
	"encoding/hex"
	"encoding/json"
	"flag"
	"fmt"
	"io/ioutil"
	"log"
	"net"
	"os"
	"os/signal"
	"path"

	"github.com/google/gopacket"
	"github.com/google/gopacket/layers"
	"github.com/markkurossi/cloudsdk/api/auth"
	"github.com/markkurossi/vpn/cli"
	"github.com/markkurossi/vpn/dns"
	"github.com/markkurossi/vpn/ip"
	"github.com/markkurossi/vpn/tun"
)

type ProxyConfig struct {
	ClientID      string `json:"client_id"`
	ClientSecret  string `json:"client_secret"`
	TokenEndpoint string `json:"token_endpoint"`
}

func main() {
	bl := flag.String("blacklist", "", "DNS blacklist")
	doh := flag.String("doh", "", "DNS-over-HTTPS URL")
	dohProxy := flag.String("doh-proxy", "", "DNS-over-HTTPS proxy URL")
	encrypt := flag.Bool("encrypt", true,
		"Encrypt DNS-over-HTTPS proxy requests")
	srv := flag.String("dns", "", "DNS server to use (default to system DNS)")
	nopad := flag.Bool("nopad", false, "Do not PAD DoH requests")
	interactive := flag.Bool("i", false, "Interactive mode")
	verboseFlag := flag.Int("v", 0, "Verbose output")
	flag.Parse()

	if len(flag.Args()) != 0 {
		fmt.Printf("Extra arguments: %v\n", flag.Args())
		flag.Usage()
		os.Exit(1)
	}

	if *interactive {
		*verboseFlag = 0
	}

	var blacklist []dns.Labels
	var err error

	if len(*bl) > 0 {
		blacklist, err = dns.ReadBlacklist(*bl)
		if err != nil {
			log.Fatal(err)
		}
	}

	origServers, err := dns.GetServers()
	if err != nil {
		log.Fatal(err)
	}
	fmt.Printf("Current DNS servers: %v\n", origServers)

	if len(*srv) == 0 {
		if len(origServers) == 0 {
			log.Fatal("DNS server not set and could not get system DNS\n")
		}
		*srv = origServers[0]
	}

	tunnel, err := tun.Create()
	if err != nil {
		log.Fatalf("Failed to create tunnel: %s\n", err)
	}
	fmt.Printf("Tunnel: %s\n", tunnel)
	err = tunnel.Configure(tun.Config{
		LocalIP:  tun.DefaultClientIP,
		RemoteIP: tun.DefaultServerIP,
	})
	if err != nil {
		log.Fatal(err)
	}

	var proxyAddr string

	proxyIP := net.ParseIP(*srv)
	switch len(proxyIP) {
	case 4:
		proxyAddr = fmt.Sprintf("%s:53", *srv)

	case 16:
		proxyAddr = fmt.Sprintf("[%s]:53", *srv)

	default:
		log.Fatalf("Invalid proxy address: %s\n", *srv)
	}
	fmt.Printf("Starting proxy with DNS server %s\n", proxyAddr)

	proxy, err := dns.NewProxy(proxyAddr, tunnel)
	if err != nil {
		log.Fatal(err)
	}
	proxy.Verbose = *verboseFlag
	proxy.Blacklist = blacklist

	if len(*doh) > 0 {
		var oauth2Client *auth.OAuth2Client
		if len(*dohProxy) > 0 {
			cfg, err := readProxyConfig()
			if err != nil {
				log.Fatal(err)
			}
			oauth2Client = auth.NewOAuth2Client(cfg.ClientID, cfg.ClientSecret,
				cfg.TokenEndpoint)
		}
		doh, err := dns.NewDoHClient(*doh, oauth2Client, *dohProxy)
		if err != nil {
			log.Fatal(err)
		}
		doh.Encrypt = *encrypt
		proxy.DoH = doh
	}
	proxy.NoPad = *nopad

	c := make(chan os.Signal, 1)

	if *interactive {
		events := make(chan dns.Event)
		proxy.Events = events
		cli.Init(c, events)
		go cli.EventHandler(events)
	}

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

	signal.Notify(c, os.Interrupt)

	go func() {
		s := <-c
		dns.RestoreServers(origServers)
		cli.Reset()
		fmt.Println("signal", s)
		os.Exit(0)
	}()

	for {
		data, err := tunnel.Read()
		if err != nil {
			log.Fatal(err)
		}

		// Check IP version.
		var firstLayerDecoder gopacket.Decoder
		version := data[0] >> 4
		switch data[0] >> 4 {
		case 4:
			firstLayerDecoder = layers.LayerTypeIPv4

		case 6:
			firstLayerDecoder = layers.LayerTypeIPv6

		default:
			log.Printf("Invalid IP version %d\n", version)
			continue
		}

		packet := gopacket.NewPacket(data, firstLayerDecoder,
			gopacket.DecodeOptions{
				Lazy:   true,
				NoCopy: true,
			})

		if layer := packet.Layer(layers.LayerTypeICMPv4); layer != nil {
			icmp, _ := layer.(*layers.ICMPv4)
			response, err := ip.ICMPv4Response(packet, icmp)
			if err != nil {
				fmt.Printf("Failed to create ICMPv4 response: %v\n", err)
			} else if response != nil {
				_, err = tunnel.Write(response)
				if err != nil {
					fmt.Printf("Failed to send ICMPv4 response: %v\n", err)
				}
			}
			continue
		}
		if layer := packet.Layer(layers.LayerTypeDNS); layer != nil {
			dns, _ := layer.(*layers.DNS)
			if !dns.QR {
				go func() {
					err := proxy.Query(packet, dns)
					if err != nil {
						fmt.Printf("DNS query failed: %s\n", err)
					}
				}()
			}
			continue
		}

		fmt.Printf("Unhandled packet:%s\n", packet)
		if *verboseFlag > 0 {
			fmt.Printf("%s", hex.Dump(data))
		}
	}
}

func readProxyConfig() (*ProxyConfig, error) {
	dir, err := os.UserHomeDir()
	if err != nil {
		return nil, fmt.Errorf("Error getting user home directory: %s", err)
	}
	path := path.Join(dir, ".doh-proxy.conf")
	file, err := os.Open(path)
	if err != nil {
		return nil, fmt.Errorf("Error opening '%s': %s", path, err)
	}
	defer file.Close()

	data, err := ioutil.ReadAll(file)
	if err != nil {
		return nil, fmt.Errorf("Error reading '%s': %s", path, err)
	}
	config := new(ProxyConfig)
	err = json.Unmarshal(data, config)
	if err != nil {
		return nil, fmt.Errorf("Error parsing '%s': %s", path, err)
	}
	return config, nil
}
