//
// dns_linux.go
//
// Copyright (c) 2019 Markku Rossi
//
// All rights reserved.
//

package dns

import (
	"fmt"
)

func GetServers() ([]string, error) {
	return nil, fmt.Errorf("GetServers not implemented yet")
}

func SetServers(servers []string) error {
	return fmt.Errorf("SetServers not implemented yet")
}

func RestoreServers(servers []string) error {
	return fmt.Errorf("RestoreServers not implemented yet")
}

func FlushCache() error {
	return fmt.Errorf("FlushCache not implemented yet")
}
