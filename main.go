//
// main.go
//
// Copyright (c) 2019-2024 Markku Rossi
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
	"github.com/markkurossi/vpn/ifmon"
	"github.com/markkurossi/vpn/ip"
	"github.com/markkurossi/vpn/tun"
)

// ProxyConfig defines proxy configuration information.
type ProxyConfig struct {
	ClientID      string `json:"client_id"`
	ClientSecret  string `json:"client_secret"`
	TokenEndpoint string `json:"token_endpoint"`
}

var (
	tunnel      *tun.Tunnel
	proxy       *dns.Proxy
	verbose     int
	origServers []string
)

func main() {
	bl := flag.String("blacklist", "", "DNS blacklist")
	doh := flag.String("doh", "", "DNS-over-HTTPS URL")
	dohProxy := flag.String("doh-proxy", "", "DNS-over-HTTPS proxy URL")
	encrypt := flag.Bool("encrypt", true,
		"Encrypt DNS-over-HTTPS proxy requests")
	srv := flag.String("dns", "", "DNS server to use (default to system DNS)")
	nopad := flag.Bool("nopad", false, "Do not PAD DoH requests")
	interactive := flag.Bool("i", false, "Interactive mode")
	flag.IntVar(&verbose, "v", 0, "Verbose output")
	flag.Parse()

	if len(flag.Args()) != 0 {
		fmt.Printf("Extra arguments: %v\n", flag.Args())
		flag.Usage()
		os.Exit(1)
	}

	if *interactive {
		verbose = 0
	}

	var blacklist []dns.Labels
	var err error

	if len(*bl) > 0 {
		blacklist, err = dns.ReadBlacklist(*bl)
		if err != nil {
			log.Fatal(err)
		}
	}

	origServers, err = dns.GetServers()
	if err != nil {
		log.Fatal(err)
	}
	fmt.Printf("Current DNS servers: %v\n", origServers)

	ifmonC := make(chan bool)

	if len(*srv) == 0 {
		if len(origServers) == 0 {
			log.Fatal("DNS server not set and could not get system DNS\n")
		}
		*srv = origServers[0]
		go listenInterfaceChanges(ifmonC)
	}

	tunnel, err = tun.Create()
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

	proxyAddr := makeDNSAddr(*srv)

	fmt.Printf("Starting proxy with DNS server %s\n", proxyAddr)

	proxy, err = dns.NewProxy(proxyAddr, tunnel)
	if err != nil {
		log.Fatal(err)
	}
	proxy.Verbose = verbose
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

	signalC := make(chan os.Signal, 1)

	if *interactive {
		eventC := make(chan dns.Event)
		proxy.Events = eventC
		cli.Init(signalC, eventC)
		go cli.EventHandler(eventC)

		eventC <- dns.Event{
			Type:   dns.EventConfig,
			Labels: []string{proxyAddr},
		}
	}

	fmt.Printf("Setting proxy DNS server\n")
	err = dns.SetServers([]string{"192.168.192.254"})
	if err != nil {
		log.Fatalf("Failed to set proxy DNS: %s\n", err)
	}
	fmt.Printf("Flushing DNS cache\n")
	err = dns.FlushCache()
	if err != nil {
		log.Printf("Failed to flush DNS cache: %s", err)
	}

	signal.Notify(signalC, os.Interrupt)

	packetC := make(chan []byte)
	go func() {
		for {
			data, err := tunnel.Read()
			if err != nil {
				log.Fatal(err)
			}
			packetC <- data
		}
	}()

	for {
		select {
		case s := <-signalC:
			cli.Reset()
			dns.RestoreServers(origServers)
			fmt.Println("signal", s)
			os.Exit(0)

		case <-ifmonC:
			log.Printf("interface change")
			dns.RestoreServers(origServers)
			origServers, err = dns.GetServers()
			if err != nil {
				// Getting DNS servers can fail. In that case will
				// wait not set the new server for the proxy below and
				// wait for a new interface change notification.
				log.Printf("Failed to get DNS servers: %v", err)
			}
			err = dns.SetServers([]string{"192.168.192.254"})
			if err != nil {
				log.Fatalf("Failed to set proxy DNS: %s", err)
			}
			fmt.Printf("Flushing DNS cache\n")
			err = dns.FlushCache()
			if err != nil {
				log.Printf("Failed to flush DNS cache: %s", err)
			}

			if len(origServers) > 0 {
				proxyAddr := makeDNSAddr(origServers[0])
				log.Printf("DNS server: %v", proxyAddr)
				err = proxy.SetServer(proxyAddr)
				if err != nil {
					log.Printf("failed to set DNS server %v: %v",
						proxyAddr, err)
				}
			}

		case data := <-packetC:
			err = handlePacket(data)
			if err != nil {
				log.Print(err)
			}
		}
	}
}

func handlePacket(data []byte) error {
	// Check IP version.
	var firstLayerDecoder gopacket.Decoder
	version := data[0] >> 4
	switch data[0] >> 4 {
	case 4:
		firstLayerDecoder = layers.LayerTypeIPv4

	case 6:
		firstLayerDecoder = layers.LayerTypeIPv6

	default:
		return fmt.Errorf("invalid IP version %d", version)
	}

	packet := gopacket.NewPacket(data, firstLayerDecoder,
		gopacket.DecodeOptions{
			Lazy:   true,
			NoCopy: true,
		})

	if layer := packet.Layer(layers.LayerTypeICMPv4); layer != nil {
		icmp := layer.(*layers.ICMPv4)
		response, err := ip.ICMPv4Response(packet, icmp)
		if err != nil {
			return err
		}
		if response != nil {
			_, err = tunnel.Write(response)
			if err != nil {
				return err
			}
		}
		return nil
	}
	if layer := packet.Layer(layers.LayerTypeDNS); layer != nil {
		dns := layer.(*layers.DNS)
		if !dns.QR {
			go func() {
				err := proxy.Query(packet, dns)
				if err != nil {
					fmt.Printf("DNS query failed: %s\n", err)
				}
			}()
		}
		return nil
	}
	// Check for mDNS packets (multicast to 5353).
	if layer := packet.Layer(layers.LayerTypeUDP); layer != nil {
		udp := layer.(*layers.UDP)
		if udp.SrcPort == 5353 && udp.DstPort == 5353 {
			log.Printf("mDNS:\n%s", hex.Dump(data))
		}
		return nil
	}

	if verbose > 0 {
		fmt.Printf("Unhandled packet: %s\n", packet)
		fmt.Printf("%s", hex.Dump(data))
	}
	return nil
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

func listenInterfaceChanges(c chan bool) {
	l, err := ifmon.Create()
	if err != nil {
		log.Fatal(err)
	}
	for {
		err = l.Wait()
		if err != nil {
			log.Fatal(err)
		}
		c <- true
	}
}

func makeDNSAddr(server string) string {
	proxyIP := net.ParseIP(server)
	switch len(proxyIP) {
	case 4:
		return fmt.Sprintf("%s:53", server)

	case 16:
		return fmt.Sprintf("[%s]:53", server)

	default:
		log.Fatalf("Invalid proxy address: %s", server)
		return ""
	}
}
