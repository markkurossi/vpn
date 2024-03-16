//
// client.go
//
// Copyright (c) 2019-2024 Markku Rossi
//
// All rights reserved.
//

package dns

import (
	"errors"
	"fmt"
	"net"
	"sync"
	"time"

	"github.com/google/gopacket"
	"github.com/google/gopacket/layers"
)

var (
	// ErrorTimeout defines a timeout error.
	ErrorTimeout = errors.New("timeout")
)

// UDPClient implements an UDP client.
type UDPClient struct {
	Server string
	Conn   net.Conn
	C      chan []byte
}

// NewUDPClient creates a new UDP client.
func NewUDPClient(server string, c chan []byte) (*UDPClient, error) {
	conn, err := net.Dial("udp", server)
	if err != nil {
		return nil, err
	}

	client := &UDPClient{
		Server: server,
		Conn:   conn,
		C:      c,
	}
	go client.reader()
	return client, nil
}

func (dns *UDPClient) reader() error {
	var buf [1500]byte
	for {
		n, err := dns.Conn.Read(buf[:])
		if err != nil {
			return err
		}
		msg := make([]byte, n)
		copy(msg, buf[:n])
		dns.C <- msg
	}
}

// Close closes the UDP client.
func (dns *UDPClient) Close() error {
	return dns.Conn.Close()
}

func (dns *UDPClient) Write(data []byte) error {
	_, err := dns.Conn.Write(data)
	return err
}

// Client implements DNS client.
type Client struct {
	udp     *UDPClient
	readerC chan []byte
	nextID  uint16
	m       sync.Mutex
	pending map[uint16]chan *layers.DNS
}

// NewClient creates a new DNS client.
func NewClient(server string) (*Client, error) {
	readerC := make(chan []byte)
	udp, err := NewUDPClient(server, readerC)
	if err != nil {
		close(readerC)
		return nil, err
	}
	client := &Client{
		udp:     udp,
		readerC: readerC,
		nextID:  1,
		pending: make(map[uint16]chan *layers.DNS),
	}
	go client.handler()

	return client, nil
}

func (client *Client) handler() {
	for resp := range client.readerC {
		packet := gopacket.NewPacket(resp, layers.LayerTypeDNS, decodeOptions)
		layer := packet.Layer(layers.LayerTypeDNS)
		if layer == nil {
			fmt.Printf("Invalid response: %s\n", packet)
			continue
		}
		dns, _ := layer.(*layers.DNS)

		client.m.Lock()
		ch, ok := client.pending[dns.ID]
		client.m.Unlock()
		if ok {
			ch <- dns
		} else {
			fmt.Printf("Unknown request %d\n", dns.ID)
		}
	}
}

// ResolveResult provides DNS resolve results.
type ResolveResult struct {
	Address  string
	NotAfter time.Time
}

// Resolve resolves the DNS name.
func (client *Client) Resolve(name string) ([]ResolveResult, error) {
	q := &layers.DNS{
		ID:     client.nextID,
		QR:     false,
		OpCode: layers.DNSOpCodeQuery,
		RD:     true,
		Questions: []layers.DNSQuestion{
			{
				Name:  []byte(name),
				Type:  layers.DNSTypeA,
				Class: layers.DNSClassIN,
			},
		},
	}
	client.nextID++

	buffer := gopacket.NewSerializeBuffer()
	err := gopacket.SerializeLayers(buffer, serializeOptions, q)
	if err != nil {
		return nil, err
	}

	ch := make(chan *layers.DNS)

	client.m.Lock()
	client.pending[q.ID] = ch
	client.m.Unlock()

	defer client.completeRequest(q.ID)

	start := time.Now()

	err = client.udp.Write(buffer.Bytes())
	if err != nil {
		return nil, err
	}

	select {
	case resp := <-ch:
		var result []ResolveResult
		for _, ans := range resp.Answers {
			notAfter := start.Add(time.Duration(ans.TTL) * time.Second)
			if ans.Type == layers.DNSTypeA {
				result = append(result, ResolveResult{
					Address:  ans.String(),
					NotAfter: notAfter,
				})
			}
		}
		return result, nil

	case <-time.After(5 * time.Second):
		return nil, ErrorTimeout
	}
}

func (client *Client) completeRequest(id uint16) {
	client.m.Lock()
	ch, ok := client.pending[id]
	delete(client.pending, id)
	client.m.Unlock()

	if !ok {
		return
	}
	// Drain channel.
	select {
	case <-ch:
	default:
	}
	close(ch)
}
