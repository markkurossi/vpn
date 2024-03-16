//
// proxy.go
//
// Copyright (c) 2019-2024 Markku Rossi
//
// All rights reserved.
//

package dns

import (
	"crypto/rand"
	"encoding/binary"
	"encoding/hex"
	"fmt"
	"io"
	"log"
	"sync"
	"time"

	"github.com/google/gopacket"
	"github.com/google/gopacket/layers"
)

var (
	bo = binary.BigEndian
)

// Proxy defines a DNS proxy.
type Proxy struct {
	Verbose     int
	Blacklist   []Labels
	Events      chan Event
	DoH         *DoHClient
	NoPad       bool
	chResponses chan []byte
	client      *UDPClient
	out         io.Writer
	m           sync.Mutex
	pending     map[uint16]*Pending
}

// Pending defines a pending DNS query.
type Pending struct {
	timestamp time.Time
	packet    gopacket.Packet
	id        uint16
}

// EventType defines proxy events.
type EventType int

// Proxy event types.
const (
	EventQuery EventType = iota
	EventBlock
	EventConfig
)

var eventTypes = map[EventType]string{
	EventQuery:  "?",
	EventBlock:  "\u00d7",
	EventConfig: "\u2672",
}

func (t EventType) String() string {
	name, ok := eventTypes[t]
	if ok {
		return name
	}
	return fmt.Sprintf("{EventType %d}", t)
}

var decodeOptions = gopacket.DecodeOptions{
	Lazy:   true,
	NoCopy: true,
}

var serializeOptions = gopacket.SerializeOptions{
	FixLengths:       true,
	ComputeChecksums: true,
}

// Event defines proxy events.
type Event struct {
	Type   EventType
	Labels Labels
}

// NewProxy creates a new DNS proxy.
func NewProxy(server string, out io.Writer) (*Proxy, error) {
	proxy := &Proxy{
		out:     out,
		pending: make(map[uint16]*Pending),
	}
	err := proxy.SetServer(server)
	if err != nil {
		return nil, err
	}
	return proxy, nil
}

// SetServer sets the DNS server to use for the proxy queries.
func (p *Proxy) SetServer(server string) error {
	ch := make(chan []byte)
	client, err := NewUDPClient(server, ch)
	if err != nil {
		close(ch)
		return err
	}

	p.m.Lock()
	old := p.client
	p.client = client
	p.chResponses = ch
	p.m.Unlock()

	go p.reader(client)

	if old != nil {
	}

	return nil
}

// Query starts a new DNS query.
func (p *Proxy) Query(packet gopacket.Packet, dns *layers.DNS) error {
	var qPassthrough bool

	for _, q := range dns.Questions {
		labels := NewLabels(string(q.Name))
		for _, black := range p.Blacklist {
			if labels.Match(black) {
				if p.Verbose > 1 {
					fmt.Printf(" \U0001F6D1 %s (%s)\n", labels, black)
				}
				p.event(EventBlock, labels)
				return p.nonExistingDomain(packet, dns)
			}
		}
		if p.DoH != nil && p.DoH.Passthrough(labels.String()) {
			qPassthrough = true
		}
		if p.Verbose > 0 {
			marker := "\u2705"
			if qPassthrough {
				marker = "\u2B50"
			}
			fmt.Printf(" %s %s %s %s\n", marker, labels, q.Type, q.Class)
		}
		p.event(EventQuery, labels)
	}

	data := dns.Contents

	// RFC 8467 padding.
	if !p.NoPad && p.DoH != nil && !qPassthrough {
		dataLen := len(data)

		// Does the request have OPT record?
		var opt *layers.DNSResourceRecord
		for _, add := range dns.Additionals {
			if add.Type == layers.DNSTypeOPT {
				opt = &add
				break
			}
		}
		if opt == nil {
			// Add OPT record.
			dns.Additionals = append(dns.Additionals, layers.DNSResourceRecord{
				Type:  layers.DNSTypeOPT,
				Class: 4096,
				TTL:   0,
			})
			opt = &dns.Additionals[len(dns.Additionals)-1]
			dataLen += 11
		}
		// Does the OPT record have a padding?
		var pad *layers.DNSOPT
		for _, o := range opt.OPT {
			if o.Code == layers.DNSOptionCodePadding {
				pad = &o
				break
			}
		}
		if pad == nil {
			dataLen += 4
			// Pad to the closest multiple of 128 octects.
			var padLen int
			if dataLen%128 != 0 {
				padLen = 128 - dataLen%128

				opt.OPT = append(opt.OPT, layers.DNSOPT{
					Code: layers.DNSOptionCodePadding,
					Data: make([]byte, padLen),
				})
			}

			// Marshal padded message.
			buffer := gopacket.NewSerializeBuffer()
			err := gopacket.SerializeLayers(buffer, serializeOptions, dns)
			if err != nil {
				return err
			}
			data = buffer.Bytes()
			if p.Verbose > 2 {
				fmt.Printf("Padded query: pad=%d:\n%s", padLen, hex.Dump(data))
			}
		}
	}

	pending := &Pending{
		timestamp: time.Now(),
		packet:    packet,
		id:        dns.ID,
	}

	// Allocate ID
	p.m.Lock()
	var id uint16
	client := p.client
	chResponses := p.chResponses
idalloc:
	for {
		var idbuf [2]byte

		for i := 0; i < 10; i++ {
			rand.Read(idbuf[:])
			id = bo.Uint16(idbuf[:])
			_, ok := p.pending[id]
			if !ok {
				p.pending[id] = pending
				break idalloc
			}
		}
		limit := time.Now().Add(-30 * time.Second)
		for id, pend := range p.pending {
			if pend.timestamp.Before(limit) {
				delete(p.pending, id)
			}
		}
	}
	p.m.Unlock()

	bo.PutUint16(data, uint16(id))

	if qPassthrough && len(dns.Questions) > 1 {
		return fmt.Errorf("Quering DoH server with multiple questions")
	}

	if p.DoH != nil && !qPassthrough {
		resp, err := p.DoH.Do(data)
		if err != nil {
			return err
		}
		chResponses <- resp
		return nil
	}

	return client.Write(data)
}

func (p *Proxy) event(t EventType, labels Labels) {
	if p.Events == nil {
		return
	}
	p.Events <- Event{
		Type:   t,
		Labels: labels,
	}
}

func (p *Proxy) nonExistingDomain(packet gopacket.Packet, q *layers.DNS) error {
	responseLayers, err := udpResponse(packet)
	if err != nil {
		return err
	}

	responseLayers = append(responseLayers, &layers.DNS{
		ID:           q.ID,
		QR:           true,
		OpCode:       q.OpCode,
		AA:           true, // XXX false in example,
		TC:           false,
		RD:           q.RD,
		RA:           false,
		ResponseCode: layers.DNSResponseCodeNXDomain,
		Questions:    q.Questions,
	})

	buffer := gopacket.NewSerializeBuffer()
	err = gopacket.SerializeLayers(buffer, serializeOptions, responseLayers...)
	if err != nil {
		return err
	}

	_, err = p.out.Write(buffer.Bytes())

	return err
}

func (p *Proxy) reader(client *UDPClient) {
	for msg := range client.C {

		packet := gopacket.NewPacket(msg, layers.LayerTypeDNS, decodeOptions)
		layer := packet.Layer(layers.LayerTypeDNS)
		if layer == nil {
			log.Printf("Proxy: non-DNS server message\n")
			continue
		}
		dns, _ := layer.(*layers.DNS)

		if p.Verbose > 2 {
			log.Printf("DNS server response:\n%s", hex.Dump(msg))
		}

		var pending *Pending
		var ok bool
		p.m.Lock()
		pending, ok = p.pending[dns.ID]
		if ok {
			delete(p.pending, dns.ID)
		}
		p.m.Unlock()

		if !ok {
			log.Printf("Unknown server response:\n%s", hex.Dump(msg))
			continue
		}

		// Restore original request ID
		dns.ID = pending.id

		response, err := udpResponse(pending.packet)
		if err != nil {
			log.Printf("Can't create UDP response: %s\n", err)
			continue
		}
		response = append(response, dns)

		buffer := gopacket.NewSerializeBuffer()
		err = gopacket.SerializeLayers(buffer, serializeOptions, response...)
		if err != nil {
			log.Printf("Serialization error: %s\n", err)
			continue
		}

		_, err = p.out.Write(buffer.Bytes())
		if err != nil {
			log.Printf("Failed to write UDP response: %s\n", err)
		}
	}
}

func udpResponse(packet gopacket.Packet) ([]gopacket.SerializableLayer, error) {
	var result []gopacket.SerializableLayer

	var ipLayer gopacket.NetworkLayer
	layer := packet.Layer(layers.LayerTypeIPv4)
	if layer != nil {
		ip, _ := layer.(*layers.IPv4)
		ip4Layer := *ip
		ip4Layer.SrcIP = ip.DstIP
		ip4Layer.DstIP = ip.SrcIP
		result = append(result, &ip4Layer)

		ipLayer = &ip4Layer
	} else {
		layer := packet.Layer(layers.LayerTypeIPv6)
		if layer == nil {
			return nil, fmt.Errorf("not an IP packet")
		}
		ip, _ := layer.(*layers.IPv6)
		ip6Layer := *ip
		ip6Layer.SrcIP = ip.DstIP
		ip6Layer.DstIP = ip.SrcIP
		result = append(result, &ip6Layer)

		ipLayer = &ip6Layer
	}

	layer = packet.Layer(layers.LayerTypeUDP)
	if layer == nil {
		return nil, fmt.Errorf("no UPD layer in request")
	}
	udp, _ := layer.(*layers.UDP)
	udpLayer := *udp
	udpLayer.SrcPort = udp.DstPort
	udpLayer.DstPort = udp.SrcPort
	udpLayer.SetNetworkLayerForChecksum(ipLayer)

	result = append(result, &udpLayer)

	return result, nil
}
