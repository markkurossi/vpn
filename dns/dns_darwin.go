//
// dns_darwin.go
//
// Copyright (c) 2019 Markku Rossi
//
// All rights reserved.
//

package dns

import (
	"fmt"
	"os/exec"
	"regexp"
)

var (
	reServer = regexp.MustCompilePOSIX(`[[:space:]]+nameserver\[[[:digit:]]+\][[:space:]]+:[[:space:]]+([[:^space:]]+)`)
)

func GetServers() ([]string, error) {
	// $ scutil --dns | grep nameserver
	// nameserver[0] : 192.168.99.1
	// nameserver[0] : 192.168.99.1

	cmd := exec.Command("scutil", "--dns")
	output, err := cmd.Output()
	if err != nil {
		return nil, err
	}
	matches := reServer.FindAllStringSubmatch(string(output), -1)
	if matches == nil {
		return nil, fmt.Errorf("Nameservers not found")
	}
	var result []string
	seen := make(map[string]bool)

	for _, m := range matches {
		_, ok := seen[m[1]]
		if !ok {
			result = append(result, m[1])
			seen[m[1]] = true
		}
	}
	return result, nil
}

func SetServers(servers []string) error {
	if len(servers) == 0 {
		return fmt.Errorf("no DNS servers specified")
	}
	// networksetup -setdnsservers Wi-Fi 192.168.192.254
	args := []string{"networksetup", "-setdnsservers", "Wi-Fi"}
	args = append(args, servers...)

	return exec.Command(args[0], args[1:]...).Run()
}

func RestoreServers(servers []string) error {
	// networksetup -setdnsservers Wi-Fi empty
	args := []string{"networksetup", "-setdnsservers", "Wi-Fi", "empty"}
	return exec.Command(args[0], args[1:]...).Run()
}

func FlushCache() error {
	for _, cmd := range [][]string{
		[]string{"killall", "-HUP", "mDNSResponder"},
		[]string{"killall", "mDNSResponderHelper"},
		[]string{"dscacheutil", "-flushcache"},
	} {
		err := exec.Command(cmd[0], cmd[1:]...).Run()
		if err != nil {
			return err
		}
	}
	return nil
}
