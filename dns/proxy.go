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
	Client  *Client
	Address string
	Out     io.Writer
	M       sync.Mutex
	Pending map[ID]*Pending
}

type Pending struct {
	timestamp time.Time
	udp       *ip.UDP
	id        ID
}

func NewProxy(server, address string, out io.Writer) (*Proxy, error) {
	client, err := NewClient(server)
	if err != nil {
		return nil, err
	}
	proxy := &Proxy{
		Client:  client,
		Address: address,
		Out:     out,
		Pending: make(map[ID]*Pending),
	}
	go proxy.reader()
	return proxy, nil
}

var blacklist = []Labels{
	[]string{"*", "adnxs", "com"},
	[]string{"*", "adform", "net"},
	[]string{"*", "hotjar", "com"},
	[]string{"*", "krxd", "net"},
	[]string{"*", "doubleclick", "net"},
	[]string{"*", "scorecardresearch", "com"},
	[]string{"*", "ensighten", "com"},
	[]string{"*", "adsafeprotected", "com"},
	[]string{"*", "googlesyndication", "com"},
	[]string{"*", "rubiconproject", "com"},
	[]string{"*", "adformnet", "akadns", "net"},
	[]string{"*", "amazon-adsystem", "com"},
	[]string{"*", "smartadserver", "com"},
	[]string{"ad", "ilcdn", "fi"},
	[]string{"ad", "markkurossi", "com"},
}

func (p *Proxy) Query(udp *ip.UDP, dns *DNS) error {
	for _, q := range dns.Questions {
		for _, black := range blacklist {
			if q.Labels.Match(black) {
				if true {
					fmt.Printf(" * %s (%s)\n", q.Labels, black)
				}
				return p.nonExistingDomain(udp, dns)
			}
		}
		fmt.Printf(" ? %s %s %s\n", q.Labels, q.QTYPE, q.QCLASS)
	}

	data := udp.Data

	if len(data) < HeaderLen {
		return ip.ErrorTruncated
	}
	pending := &Pending{
		timestamp: time.Now(),
		udp:       udp,
		id:        ID(bo.Uint16(data)),
	}

	// Allocate ID
	p.M.Lock()
	var id ID
idalloc:
	for {
		var idbuf [2]byte

		for i := 0; i < 10; i++ {
			rand.Read(idbuf[:])
			id = ID(bo.Uint16(idbuf[:]))
			_, ok := p.Pending[id]
			if !ok {
				p.Pending[id] = pending
				break idalloc
			}
		}
		limit := time.Now().Add(-30 * time.Second)
		for id, pend := range p.Pending {
			if pend.timestamp.Before(limit) {
				delete(p.Pending, id)
			}
		}
	}
	p.M.Unlock()

	bo.PutUint16(data, uint16(id))

	return p.Client.Write(data)
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
	_, err = p.Out.Write(udp.Marshal())

	return err
}

func (p *Proxy) reader() {
	for msg := range p.Client.C {
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
		p.M.Lock()
		pending, ok = p.Pending[dns.ID]
		if ok {
			delete(p.Pending, dns.ID)
		}
		p.M.Unlock()

		if !ok {
			fmt.Printf("Unknown server response:\n")
			dns.Dump()
			continue
		}

		bo.PutUint16(msg, uint16(pending.id))

		pending.udp.Data = msg
		pending.udp.Swap()

		_, err = p.Out.Write(pending.udp.Marshal())
		if err != nil {
			log.Printf("Failed to write UDP response: %s\n", err)
		}
	}
}
