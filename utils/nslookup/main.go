//
// query.go
//
// Copyright (c) 2019 Markku Rossi
//
// All rights reserved.
//

package main

import (
	"flag"
	"fmt"
	"os"

	"github.com/markkurossi/vpn/dns"
)

func main() {
	server := flag.String("s", "8.8.8.8", "DNS server address")
	flag.Parse()

	srv := fmt.Sprintf("%s:53", *server)
	fmt.Printf("Using server %s\n", srv)

	client, err := dns.NewClient(srv)
	if err != nil {
		fmt.Printf("Failed to create DNS client: %s\n", err)
		os.Exit(1)
	}

	for _, arg := range flag.Args() {
		fmt.Printf("? %s\n", arg)

		result, err := client.Resolve(arg)
		if err != nil {
			fmt.Printf("DNS error: %s\n", err)
			continue
		}
		fmt.Printf("Result: %s\n", result)
	}
}
