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
	"encoding/base64"
	"encoding/json"
	"fmt"
	"io/ioutil"
	"net/http"
	"net/url"
	"regexp"

	"github.com/markkurossi/cicd/api/auth"
)

var (
	reServerPort = regexp.MustCompilePOSIX(`^(.*):[[:digit:]]+$`)
)

type DoHClient struct {
	URL     string
	servers []string
	http    *http.Client
	oauth2  *auth.OAuth2Client
	proxy   string
	token   string
}

func NewDoHClient(server string, oauth2 *auth.OAuth2Client, proxy string) (
	*DoHClient, error) {

	client := &DoHClient{
		URL:    server,
		http:   new(http.Client),
		oauth2: oauth2,
		proxy:  proxy,
	}

	if oauth2 != nil {
		err := client.AddPassthrough(oauth2.TokenEndpoint)
		if err != nil {
			return nil, err
		}
	}
	if len(proxy) != 0 {
		err := client.AddPassthrough(proxy)
		if err != nil {
			return nil, err
		}
	} else {
		err := client.AddPassthrough(server)
		if err != nil {
			return nil, err
		}
	}

	return client, nil
}

func (doh *DoHClient) AddPassthrough(u string) error {
	parsed, err := url.Parse(u)
	if err != nil {
		return err
	}
	var server string
	m := reServerPort.FindStringSubmatch(parsed.Host)
	if m == nil {
		server = parsed.Host
	} else {
		server = m[1]
	}

	fmt.Printf("Server: %s\n", server)
	doh.servers = append(doh.servers, server)
	return nil
}

func (doh *DoHClient) Passthrough(host string) bool {
	for _, server := range doh.servers {
		if server == host {
			return true
		}
	}
	return false
}

func (doh *DoHClient) Do(data []byte) ([]byte, error) {
	if len(doh.proxy) == 0 {
		return doh.doDoH(data)
	} else {
		return doh.doDoHProxy(data)
	}
}

func (doh *DoHClient) doDoH(data []byte) ([]byte, error) {
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
	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("HTTP error: %s", resp.Status)
	}
	return ioutil.ReadAll(resp.Body)
}

func (doh *DoHClient) doDoHProxy(data []byte) ([]byte, error) {

	reqData, err := json.Marshal(map[string]string{
		"data":   base64.RawURLEncoding.EncodeToString(data),
		"server": doh.URL,
	})
	if err != nil {
		return nil, err
	}

	for {
		if len(doh.token) == 0 {
			token, err := doh.oauth2.GetToken()
			if err != nil {
				return nil, fmt.Errorf("OAuth2 error: %s", err)
			}
			doh.token = token.AccessToken
		}

		req, err := http.NewRequest("POST", doh.proxy, bytes.NewReader(reqData))
		if err != nil {
			return nil, err
		}
		req.Header.Set("Content-Type", "application/json;charset=UTF-8")
		req.Header.Set("Authorization", fmt.Sprintf("Bearer %s", doh.token))

		resp, err := doh.http.Do(req)
		if err != nil {
			return nil, err
		}
		defer resp.Body.Close()

		result, err := ioutil.ReadAll(resp.Body)
		if err != nil {
			return nil, err
		}

		switch resp.StatusCode {
		case http.StatusOK:
			return result, nil

		case http.StatusUnauthorized:
			return nil, fmt.Errorf("Unauthorized: %s",
				resp.Header.Get("WWW-Authenticate"))

		default:
			return nil, fmt.Errorf("HTTP error: %s", string(result))
		}
	}
}
