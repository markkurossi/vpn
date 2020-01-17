//
// main.go
//
// Copyright (c) 2019-2020 Markku Rossi
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
	"os"
	"os/signal"
	"path"

	"github.com/markkurossi/cicd/api/auth"
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

	proxyAddr := fmt.Sprintf("%s:53", *srv)
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

	if *interactive {
		events := make(chan dns.Event)
		proxy.Events = events
		cli.Init()
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

	c := make(chan os.Signal, 1)
	signal.Notify(c, os.Interrupt)

	go func() {
		s := <-c
		fmt.Println("signal", s)
		dns.RestoreServers(origServers)
		cli.Reset()
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
			if *verboseFlag > 0 {
				fmt.Printf("%s: packet:\n%s", err, hex.Dump(data))
			}
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
							fmt.Printf("DNS query failed: %s\n", err)
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
