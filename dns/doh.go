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
	"io/ioutil"
	"net/http"
)

type DoHClient struct {
	URL  string
	http *http.Client
}

func NewDoHClient(url string) *DoHClient {
	return &DoHClient{
		URL:  url,
		http: new(http.Client),
	}
}

func (doh *DoHClient) Do(data []byte) ([]byte, error) {
	req, err := http.NewRequest("POST", doh.URL, bytes.NewReader(data))
	if err != nil {
		return nil, err
	}
	req.Header.Set("Content-Type", "application/dns-message")

	// XXX The URL's host must be replaced by its IP address and host
	// set to `req.Host`. This means that we must have resolver here.
	req.Host = "dns.google"
	resp, err := doh.http.Do(req)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()
	return ioutil.ReadAll(resp.Body)
}
