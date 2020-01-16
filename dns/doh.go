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
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha256"
	"crypto/x509"
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
	cert    *x509.Certificate
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

	for retryCount := 0; retryCount < 2; retryCount++ {
		if len(doh.token) == 0 {
			token, err := doh.oauth2.GetToken()
			if err != nil {
				return nil, fmt.Errorf("OAuth2 error: %s", err)
			}
			doh.token = token.AccessToken
		}

		reqData, key, err := doh.CreatePayload(data)
		if err != nil {
			return nil, err
		}

		req, err := http.NewRequest("POST", doh.proxy+"/dns-query",
			bytes.NewReader(reqData))
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
			return Decrypt(key[:32], key[32+12:], result)

		case http.StatusUnauthorized:
			return nil, fmt.Errorf("Unauthorized: %s",
				resp.Header.Get("WWW-Authenticate"))

		default:
			return nil, fmt.Errorf("HTTP error: %s", string(result))
		}
	}
	return nil, fmt.Errorf("can't connect to DoH proxy")
}

func (doh *DoHClient) Certificate() (*x509.Certificate, error) {
	if doh.cert == nil {
		req, err := http.NewRequest("GET", doh.proxy+"/certificate", nil)
		if err != nil {
			return nil, err
		}
		req.Header.Set("Authorization", fmt.Sprintf("Bearer %s", doh.token))
		resp, err := doh.http.Do(req)
		if err != nil {
			return nil, err
		}
		defer resp.Body.Close()

		data, err := ioutil.ReadAll(resp.Body)
		if err != nil {
			return nil, err
		}
		if resp.StatusCode != http.StatusOK {
			return nil, fmt.Errorf("failed to get certificate: %s: %s",
				resp.Status, string(data))
		}

		doh.cert, err = x509.ParseCertificate(data)
		if err != nil {
			return nil, err
		}
		fmt.Printf("Certificate: %s %s\n", doh.cert.Subject, doh.cert.NotAfter)
	}

	return doh.cert, nil
}

func (doh *DoHClient) CreatePayload(q []byte) ([]byte, []byte, error) {
	cert, err := doh.Certificate()
	if err != nil {
		return nil, nil, err
	}

	var key [32 + 2*12]byte
	_, err = rand.Read(key[:])
	if err != nil {
		return nil, nil, err
	}

	// Encrypt query.

	payload, err := json.Marshal(map[string]string{
		"data":   base64.RawURLEncoding.EncodeToString(q),
		"server": doh.URL,
	})
	if err != nil {
		return nil, nil, err
	}
	qEnc, err := Encrypt(key[:32], key[32:32+12], payload)
	if err != nil {
		return nil, nil, err
	}

	// Encrypt payload encryption key with proxy public key.

	var keyEnc []byte

	switch pub := cert.PublicKey.(type) {
	case *rsa.PublicKey:
		keyEnc, err = rsa.EncryptOAEP(sha256.New(), rand.Reader, pub,
			key[:], nil)
		if err != nil {
			return nil, nil, err
		}

	default:
		return nil, nil,
			fmt.Errorf("Unsupported public key: %T", cert.PublicKey)
	}

	// Create DNS query payload.
	data, err := json.Marshal(map[string]interface{}{
		"data": base64.RawURLEncoding.EncodeToString(qEnc),
		"key": map[string]interface{}{
			"id":   cert.SerialNumber.String(),
			"data": base64.RawURLEncoding.EncodeToString(keyEnc),
		},
	})
	if err != nil {
		return nil, nil, err
	}
	return data, key[:], nil
}

func Encrypt(key, nonce, data []byte) ([]byte, error) {
	block, err := aes.NewCipher(key)
	if err != nil {
		return nil, err
	}
	aesgcm, err := cipher.NewGCM(block)
	if err != nil {
		return nil, err
	}
	return aesgcm.Seal(nil, nonce[:], data, nil), nil
}

func Decrypt(key, nonce, data []byte) ([]byte, error) {
	block, err := aes.NewCipher(key[:])
	if err != nil {
		return nil, err
	}
	aesgcm, err := cipher.NewGCM(block)
	if err != nil {
		return nil, err
	}
	return aesgcm.Open(nil, nonce, data, nil)
}
