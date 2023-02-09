//
// blacklist.go
//
// Copyright (c) 2019-2023 Markku Rossi
//
// All rights reserved.
//

package dns

import (
	"bufio"
	"os"
	"strings"
)

// ReadBlacklist reads the blacklist from the file.
func ReadBlacklist(name string) ([]Labels, error) {
	file, err := os.Open(name)
	if err != nil {
		return nil, err
	}
	defer file.Close()

	var result []Labels

	scanner := bufio.NewScanner(file)
	for scanner.Scan() {
		line := strings.TrimSpace(scanner.Text())
		if len(line) == 0 {
			continue
		}
		if line[0] == '#' {
			continue
		}

		result = append(result, strings.Split(line, "."))
	}
	return result, scanner.Err()
}
