//
// doh.go
//
// Copyright (c) 2019 Markku Rossi
//
// All rights reserved.
//
// DNS-over-HTTPS
//

package dns

import (
	"bytes"
	"fmt"
	"io/ioutil"
	"net/http"
	"net/url"
	"regexp"
)

var (
	reServerPort = regexp.MustCompilePOSIX(`^(.*):[[:digit:]]+$`)
)

type DoHClient struct {
	URL    string
	server string
	http   *http.Client
}

func NewDoHClient(rawurl string) (*DoHClient, error) {
	parsed, err := url.Parse(rawurl)
	if err != nil {
		return nil, err
	}
	var server string
	m := reServerPort.FindStringSubmatch(parsed.Host)
	if m == nil {
		server = parsed.Host
	} else {
		server = m[1]
	}

	fmt.Printf("Server: %s\n", server)

	return &DoHClient{
		URL:    rawurl,
		server: server,
		http:   new(http.Client),
	}, nil
}

func (doh *DoHClient) IsServer(host string) bool {
	return doh.server == host
}

func (doh *DoHClient) Do(data []byte) ([]byte, error) {
	req, err := http.NewRequest("POST", doh.URL, bytes.NewReader(data))
	if err != nil {
		return nil, err
	}
	req.Header.Set("Content-Type", "application/dns-message")

	resp, err := doh.http.Do(req)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()
	return ioutil.ReadAll(resp.Body)
}
