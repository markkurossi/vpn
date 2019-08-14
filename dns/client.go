//
// client.go
//
// Copyright (c) 2019 Markku Rossi
//
// All rights reserved.
//

package dns

import (
	"net"
)

type Client struct {
	Server string
	Conn   net.Conn
	C      chan []byte
}

func NewClient(server string) (*Client, error) {
	conn, err := net.Dial("udp", server)
	if err != nil {
		return nil, err
	}

	client := &Client{
		Server: server,
		Conn:   conn,
		C:      make(chan []byte),
	}
	go client.reader()
	return client, nil
}

func (dns *Client) reader() error {
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

func (dns *Client) Write(data []byte) error {
	_, err := dns.Conn.Write(data)
	return err
}
