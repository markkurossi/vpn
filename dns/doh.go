//
// doh.go
//
// Copyright (c) 2019-2023 Markku Rossi
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
	"errors"
	"fmt"
	"io/ioutil"
	"net/http"
	"net/url"
	"regexp"
	"sync"
	"time"

	"github.com/markkurossi/cloudsdk/api/auth"
)

// DoH client constants.
const (
	NonceLen   = 12
	RetryCount = 10
)

var (
	reServerPort = regexp.MustCompilePOSIX(`^(.*):[[:digit:]]+$`)
)

// DoHClient implements a DoH client.
type DoHClient struct {
	URL     string
	servers []string
	http    *http.Client
	OAuth2  *auth.OAuth2Client
	Proxy   string
	Encrypt bool
	token   string
	certs   map[string]*Certificate
	sa      *SA
	m       *sync.Mutex
}

// SA implements a security association.
type SA struct {
	ID      string
	Key     []byte
	Created time.Time
}

// Certificate defines a certificate.
type Certificate struct {
	X509     *x509.Certificate
	LastSeen time.Time
}

// ID returns the certificate ID as string.
func (cert *Certificate) ID() string {
	return cert.X509.SerialNumber.String()
}

// Encrypt encrypts the data with the certificate.
func (cert *Certificate) Encrypt(data []byte) ([]byte, error) {
	switch pub := cert.X509.PublicKey.(type) {
	case *rsa.PublicKey:
		return rsa.EncryptOAEP(sha256.New(), rand.Reader, pub, data, nil)

	default:
		return nil, fmt.Errorf("unsupported public key: %T",
			cert.X509.PublicKey)
	}
}

// NewDoHClient creates a new DoH client.
func NewDoHClient(server string, oauth2 *auth.OAuth2Client, proxy string) (
	*DoHClient, error) {

	client := &DoHClient{
		URL:    server,
		http:   new(http.Client),
		OAuth2: oauth2,
		Proxy:  proxy,
		certs:  make(map[string]*Certificate),
		m:      new(sync.Mutex),
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
		// If proxy is at localhost, add passthrough also for server.
		proxyServer, err := getServerFromURL(proxy)
		if err != nil {
			return nil, err
		}
		switch proxyServer {
		case "localhost", "127.0.0.1", "::1":
			client.AddPassthrough(server)
		}
	} else {
		err := client.AddPassthrough(server)
		if err != nil {
			return nil, err
		}
	}

	return client, nil
}

// AddPassthrough adds a passthrough name for the client.
func (doh *DoHClient) AddPassthrough(u string) error {
	server, err := getServerFromURL(u)
	if err != nil {
		return err
	}
	fmt.Printf("Server: %s\n", server)
	doh.servers = append(doh.servers, server)
	return nil
}

func getServerFromURL(u string) (string, error) {
	parsed, err := url.Parse(u)
	if err != nil {
		return "", err
	}
	m := reServerPort.FindStringSubmatch(parsed.Host)
	if m == nil {
		return parsed.Host, nil
	}
	return m[1], nil
}

// Passthrough tests if the host is passed through to the system DNS
// resolver instead of using the DoH server.
func (doh *DoHClient) Passthrough(host string) bool {
	for _, server := range doh.servers {
		if server == host {
			return true
		}
	}
	return false
}

// Do does an DoH operation.
func (doh *DoHClient) Do(data []byte) ([]byte, error) {
	if len(doh.Proxy) == 0 {
		return doh.doDoH(data)
	}
	req, err := json.Marshal(map[string]interface{}{
		"data":   data,
		"server": doh.URL,
	})
	if err != nil {
		return nil, err
	}
	if doh.Encrypt {
		return doh.doDoHEncryptedProxy(req)
	}
	return doh.doDoHProxy(req)
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

	for retryCount := 0; retryCount < RetryCount; retryCount++ {
		token, err := doh.Token()
		if err != nil {
			return nil, err
		}

		req, err := http.NewRequest("POST", doh.Proxy+"/dns-query",
			bytes.NewReader(data))
		if err != nil {
			return nil, err
		}
		req.Header.Set("Content-Type", "application/json;charset=UTF-8")
		req.Header.Set("Authorization", fmt.Sprintf("Bearer %s", token))

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
	return nil, fmt.Errorf("can't connect to DoH proxy")
}

func (doh *DoHClient) doDoHEncryptedProxy(data []byte) ([]byte, error) {

	sa, err := doh.SA()
	if err != nil {
		return nil, err
	}

	payload, err := Encrypt(sa.Key, data)
	if err != nil {
		return nil, err
	}

	for retryCount := 0; retryCount < RetryCount; retryCount++ {
		token, err := doh.Token()
		if err != nil {
			return nil, err
		}

		req, err := http.NewRequest("POST",
			fmt.Sprintf("%s/sas/%s/dns-query", doh.Proxy, sa.ID),
			bytes.NewReader(payload))
		if err != nil {
			return nil, err
		}
		req.Header.Set("Content-Type", "application/octet-stream")
		req.Header.Set("Authorization", fmt.Sprintf("Bearer %s", token))

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
			return Decrypt(sa.Key, result)

		case http.StatusNotFound:
			// SA unknown.
			err = doh.CreateSA(sa)
			if err != nil {
				return nil, err
			}

		default:
			return nil, fmt.Errorf("HTTP error %s: %s",
				resp.Status, string(result))
		}
	}
	return nil, fmt.Errorf("can't connect to encrypted DoH proxy")
}

// SA returns a security association.
func (doh *DoHClient) SA() (*SA, error) {
	now := time.Now()

	if doh.sa == nil || doh.sa.Created.Before(now.Add(-30*time.Minute)) {
		buf := make([]byte, 32)

		// Create ID.
		_, err := rand.Read(buf[:16])
		if err != nil {
			return nil, err
		}
		id := base64.RawURLEncoding.EncodeToString(buf[:16])

		// Create key.
		_, err = rand.Read(buf)
		if err != nil {
			return nil, err
		}

		doh.sa = &SA{
			ID:      id,
			Key:     buf,
			Created: now,
		}
	}
	return doh.sa, nil
}

// CreateSA defines a create SA request.
type CreateSA struct {
	SAs []*Envelope
}

// Envelope implements an encrypted data with encryption key ID.
type Envelope struct {
	Data  []byte `json:"data"`
	KeyID string `json:"key_id"`
}

// CreateSA creates a security association with the DoH server.
func (doh *DoHClient) CreateSA(sa *SA) error {
	token, err := doh.Token()
	if err != nil {
		return err
	}

	for retryCount := 0; retryCount < RetryCount; retryCount++ {
		saReq, err := json.Marshal(map[string]interface{}{
			"id":  sa.ID,
			"key": sa.Key,
		})
		if err != nil {
			return err
		}

		// Encrypt SA request payload.

		certs, err := doh.Certificate()
		if err != nil {
			return err
		}

		var payload CreateSA

		for _, cert := range certs {
			encrypted, err := cert.Encrypt(saReq)
			if err != nil {
				return err
			}
			payload.SAs = append(payload.SAs, &Envelope{
				Data:  encrypted,
				KeyID: cert.ID(),
			})
		}

		data, err := json.Marshal(&payload)
		if err != nil {
			return err
		}

		req, err := http.NewRequest("POST", doh.Proxy+"/sas/",
			bytes.NewReader(data))
		if err != nil {
			return err
		}
		req.Header.Set("Content-Type", "application/octet-stream")
		req.Header.Set("Authorization", fmt.Sprintf("Bearer %s", token))

		resp, err := doh.http.Do(req)
		if err != nil {
			return err
		}
		defer resp.Body.Close()

		result, err := ioutil.ReadAll(resp.Body)
		if err != nil {
			return err
		}

		switch resp.StatusCode {
		case http.StatusCreated:
			_, err = doh.AddCertificate(result)
			return err

		case http.StatusFailedDependency:
			_, err := doh.AddCertificate(result)
			if err != nil {
				return err
			}

		default:
			return fmt.Errorf("HTTP error %d: %s", resp.StatusCode,
				string(result))
		}
	}
	return errors.New("SA creation failed")
}

// Token returns the OAuth2 authentication token.
func (doh *DoHClient) Token() (string, error) {
	if len(doh.token) == 0 {
		token, err := doh.OAuth2.GetToken()
		if err != nil {
			return "", fmt.Errorf("OAuth2 error: %s", err)
		}
		doh.token = token.AccessToken
	}
	return doh.token, nil
}

// Certificate returns certificates.
func (doh *DoHClient) Certificate() ([]*Certificate, error) {
	var result []*Certificate

	doh.m.Lock()
	for _, cert := range doh.certs {
		result = append(result, cert)
	}
	doh.m.Unlock()

	if len(result) > 0 {
		return result, nil
	}

	token, err := doh.Token()
	if err != nil {
		return nil, err
	}

	req, err := http.NewRequest("GET", doh.Proxy+"/certificate", nil)
	if err != nil {
		return nil, err
	}
	req.Header.Set("Authorization", fmt.Sprintf("Bearer %s", token))
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

	cert, err := doh.AddCertificate(data)
	if err != nil {
		return nil, err
	}
	result = append(result, cert)

	return result, nil
}

// AddCertificate adds certificates to the DoH client.
func (doh *DoHClient) AddCertificate(data []byte) (*Certificate, error) {
	doh.m.Lock()
	defer doh.m.Unlock()

	X509, err := x509.ParseCertificate(data)
	if err != nil {
		return nil, err
	}
	cert := &Certificate{
		X509:     X509,
		LastSeen: time.Now(),
	}
	doh.certs[cert.ID()] = cert

	return cert, nil
}

// Encrypt encrypts the data with the key.
func Encrypt(key, data []byte) ([]byte, error) {
	var nonce [NonceLen]byte

	_, err := rand.Read(nonce[:])
	if err != nil {
		return nil, err
	}

	block, err := aes.NewCipher(key)
	if err != nil {
		return nil, err
	}
	aesgcm, err := cipher.NewGCM(block)
	if err != nil {
		return nil, err
	}
	encrypted := aesgcm.Seal(nil, nonce[:], data, nil)

	return append(nonce[:], encrypted...), nil
}

// Decrypt decrypts the data with the key.
func Decrypt(key, data []byte) ([]byte, error) {
	if len(data) < NonceLen {
		return nil, fmt.Errorf("truncated encrypted payload: len=%d", len(data))
	}
	block, err := aes.NewCipher(key[:])
	if err != nil {
		return nil, err
	}
	aesgcm, err := cipher.NewGCM(block)
	if err != nil {
		return nil, err
	}
	return aesgcm.Open(nil, data[:NonceLen], data[NonceLen:], nil)
}
