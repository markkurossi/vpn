//
// dns_linux.go
//
// Copyright (c) 2019-2023 Markku Rossi
//
// All rights reserved.
//

package dns

import (
	"fmt"
	"os/exec"
	"regexp"
	"strings"
)

var (
	reLink   = regexp.MustCompilePOSIX(`^Link [[:digit:]]+ \(([^\)]+)\)`)
	reServer = regexp.MustCompilePOSIX(`^[[:space:]]*DNS Servers:[[:space:]]+([[:^space:]]+)`)
)

type server struct {
	Link    string
	Servers string
}

func getServers() ([]server, error) {
	cmd := exec.Command("systemd-resolve", "--status")
	output, err := cmd.Output()
	if err != nil {
		return nil, err
	}

	var result []server
	var link string
	for _, line := range strings.Split(string(output), "\n") {
		m := reLink.FindStringSubmatch(line)
		if m != nil {
			link = m[1]
			continue
		}
		m = reServer.FindStringSubmatch(line)
		if m != nil {
			result = append(result, server{
				Link:    link,
				Servers: m[1],
			})
		}
	}
	return result, nil
}

// GetServers returns the list of system DNS servers.
func GetServers() ([]string, error) {
	servers, err := getServers()
	if err != nil {
		return nil, err
	}
	if len(servers) == 0 {
		return nil, fmt.Errorf("DNS servers not found")
	}
	var result []string
	for _, server := range servers {
		result = append(result, server.Servers)
	}
	return result, nil
}

// SetServers sets the system DNS servers.
func SetServers(servers []string) error {
	old, err := getServers()
	if err != nil {
		return err
	}
	if len(old) == 0 {
		return fmt.Errorf("Could not get interface information")
	}
	cmd := exec.Command("systemd-resolve", "--set-dns="+servers[0],
		"-i", old[0].Link)

	return cmd.Run()
}

// RestoreServers restores the system DNS servers.
func RestoreServers(servers []string) error {
	return SetServers(servers)
}

// FlushCache flushes DNS cache.
func FlushCache() error {
	return exec.Command("systemd-resolve", "--flush-caches").Run()
}
