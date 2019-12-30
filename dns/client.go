//
// client.go
//
// Copyright (c) 2019 Markku Rossi
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
)

var (
	ErrorTimeout = errors.New("timeout")
)

type UDPClient struct {
	Server string
	Conn   net.Conn
	C      chan []byte
}

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

func (dns *UDPClient) Write(data []byte) error {
	_, err := dns.Conn.Write(data)
	return err
}

type Client struct {
	udp     *UDPClient
	readerC chan []byte
	nextID  uint16
	m       sync.Mutex
	pending map[ID]chan *DNS
}

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
		pending: make(map[ID]chan *DNS),
	}
	go client.handler()

	return client, nil
}

func (client *Client) handler() {
	for resp := range client.readerC {
		r, err := Parse(resp)
		if err != nil {
			fmt.Printf("Invalid response: %s\n", err)
			continue
		}
		r.Dump()
		client.m.Lock()
		ch, ok := client.pending[r.ID]
		client.m.Unlock()
		if ok {
			ch <- r
		} else {
			fmt.Printf("Unknown request %s\n", r.ID)
		}
	}
}

type ResolveResult struct {
	Address  string
	NotAfter time.Time
}

func (client *Client) Resolve(name string) ([]ResolveResult, error) {
	q := &DNS{
		ID:     ID(client.nextID),
		QR:     false,
		Opcode: QUERY,
		RD:     true,
		Questions: []*Question{
			&Question{
				Labels: NewLabels(name),
				QTYPE:  A,
				QCLASS: IN,
			},
		},
	}
	client.nextID++
	q.Dump()

	data, err := q.Marshal()
	if err != nil {
		return nil, err
	}

	ch := make(chan *DNS)

	client.m.Lock()
	client.pending[q.ID] = ch
	client.m.Unlock()

	defer client.completeRequest(q.ID)

	start := time.Now()

	err = client.udp.Write(data)
	if err != nil {
		return nil, err
	}

	select {
	case resp := <-ch:
		var result []ResolveResult
		for _, ans := range resp.Answers {
			notAfter := start.Add(time.Duration(ans.TTL) * time.Second)
			if ans.TYPE == A {
				if ans.RDATA.Len() == 4 {
					a := ans.RDATA.Bytes()
					result = append(result, ResolveResult{
						Address: fmt.Sprintf("%d.%d.%d.%d",
							a[0], a[1], a[2], a[3]),
						NotAfter: notAfter,
					})
				}
			}
		}
		return result, nil

	case <-time.After(5 * time.Second):
		return nil, ErrorTimeout
	}
}

func (client *Client) completeRequest(id ID) {
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
