//
// client.go
//
// Copyright (c) 2019 Markku Rossi
//
// All rights reserved.
//

package dns

import (
	"fmt"
	"net"
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
	udp    *UDPClient
	ch     chan []byte
	nextID uint16
}

func NewClient(server string) (*Client, error) {
	ch := make(chan []byte)
	udp, err := NewUDPClient(server, ch)
	if err != nil {
		close(ch)
		return nil, err
	}
	return &Client{
		udp:    udp,
		ch:     ch,
		nextID: 1,
	}, nil
}

func (client *Client) Resolve(name string) (string, error) {
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
		return "", err
	}

	err = client.udp.Write(data)
	if err != nil {
		return "", err
	}

	for resp := range client.ch {
		r, err := Parse(resp)
		if err != nil {
			return "", err
		}
		r.Dump()
		for _, ans := range r.Answers {
			if ans.TYPE == A {
				if ans.RDATA.Len() == 4 {
					a := ans.RDATA.Bytes()
					return fmt.Sprintf("%d.%d.%d.%d", a[0], a[1], a[2], a[3]),
						nil
				}
			}
		}
	}

	return "", fmt.Errorf("Not implemented yet")
}
