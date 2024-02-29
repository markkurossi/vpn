//
// Copyright (c) 2024 Markku Rossi
//
// All rights reserved.
//

package main

import (
	"log"

	"github.com/markkurossi/vpn/ifmon"
)

func main() {
	l, err := ifmon.Create()
	if err != nil {
		log.Fatalf("ifmon.Create: %v", err)
	}
	for {
		err := l.Wait()
		if err != nil {
			log.Fatalf("ifmon.Wait: %v", err)
		}
	}
}
