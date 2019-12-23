//
// proxy.go
//
// Copyright (c) 2019 Markku Rossi
//
// All rights reserved.
//

package dns

import (
	"crypto/rand"
	"fmt"
	"io"
	"log"
	"sync"
	"time"

	"github.com/markkurossi/vpn/ip"
)

type Proxy struct {
	Verbose     int
	Blacklist   []Labels
	Events      chan Event
	DoH         *DoHClient
	chResponses chan []byte
	client      *UDPClient
	address     string
	out         io.Writer
	m           sync.Mutex
	pending     map[ID]*Pending
}

type Pending struct {
	timestamp time.Time
	udp       *ip.UDP
	id        ID
}

type EventType int

const (
	EventQuery EventType = iota
	EventBlock
)

var eventTypes = map[EventType]string{
	EventQuery: "?",
	EventBlock: "'u00d7",
}

func (t EventType) String() string {
	name, ok := eventTypes[t]
	if ok {
		return name
	}
	return fmt.Sprintf("{EventType %d}", t)
}

type Event struct {
	Type   EventType
	Labels Labels
}

func NewProxy(server, address string, out io.Writer) (*Proxy, error) {
	ch := make(chan []byte)
	client, err := NewUDPClient(server, ch)
	if err != nil {
		return nil, err
	}
	proxy := &Proxy{
		chResponses: ch,
		client:      client,
		address:     address,
		out:         out,
		pending:     make(map[ID]*Pending),
	}
	go proxy.reader()
	return proxy, nil
}

func (p *Proxy) Query(udp *ip.UDP, dns *DNS) error {
	var qDoHServer bool

	for _, q := range dns.Questions {
		for _, black := range p.Blacklist {
			if q.Labels.Match(black) {
				if p.Verbose > 1 {
					fmt.Printf(" \u00d7 %s (%s)\n", q.Labels, black)
				}
				p.event(EventBlock, q.Labels)
				return p.nonExistingDomain(udp, dns)
			}
		}
		if p.DoH != nil && p.DoH.IsServer(q.Labels.String()) {
			qDoHServer = true
		}
		if p.Verbose > 0 {
			marker := "?"
			if qDoHServer {
				marker = "\u00ae"
			}
			fmt.Printf(" %s %s %s %s\n", marker, q.Labels, q.QTYPE, q.QCLASS)
		}
		p.event(EventQuery, q.Labels)
	}

	var data []byte
	var err error

	if false {
		data = udp.Data
	} else {
		data, err = dns.Marshal()
		if err != nil {
			return err
		}
	}

	if len(data) < HeaderLen {
		return ip.ErrorTruncated
	}
	pending := &Pending{
		timestamp: time.Now(),
		udp:       udp,
		id:        ID(bo.Uint16(data)),
	}

	// Allocate ID
	p.m.Lock()
	var id ID
idalloc:
	for {
		var idbuf [2]byte

		for i := 0; i < 10; i++ {
			rand.Read(idbuf[:])
			id = ID(bo.Uint16(idbuf[:]))
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

	if qDoHServer && len(dns.Questions) > 1 {
		return fmt.Errorf("Quering DoH server with multiple questions")
	}

	if p.DoH != nil && !qDoHServer {
		resp, err := p.DoH.Do(data)
		if err != nil {
			return err
		}
		p.chResponses <- resp
		return nil
	}

	return p.client.Write(data)
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

func (p *Proxy) nonExistingDomain(udp *ip.UDP, q *DNS) error {
	reply := &DNS{
		ID:        q.ID,
		QR:        true,
		Opcode:    q.Opcode,
		AA:        true, // XXX false in example,
		TC:        false,
		RD:        q.RD,
		RA:        false,
		RCODE:     NXDomain,
		Questions: q.Questions,
	}

	msg, err := reply.Marshal()
	if err != nil {
		return err
	}
	udp.Data = msg
	udp.Swap()
	_, err = p.out.Write(udp.Marshal())

	return err
}

func (p *Proxy) reader() {
	for msg := range p.client.C {
		bak := make([]byte, len(msg))
		copy(bak, msg)

		dns, err := Parse(msg)
		if err != nil {
			log.Printf("Proxy: failed to parse server message: %s\n", err)
			continue
		}
		if false {
			dns.Dump()
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
			fmt.Printf("Unknown server response:\n")
			dns.Dump()
			continue
		}

		bo.PutUint16(msg, uint16(pending.id))

		pending.udp.Data = msg
		pending.udp.Swap()

		_, err = p.out.Write(pending.udp.Marshal())
		if err != nil {
			log.Printf("Failed to write UDP response: %s\n", err)
		}
	}
}
