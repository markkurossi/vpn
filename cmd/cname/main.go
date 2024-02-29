//

package main

import (
	"flag"
	"fmt"
	"net"
)

func main() {
	flag.Parse()

	for _, a := range flag.Args() {
		cname, err := net.LookupCNAME(a)
		fmt.Printf("%s\t%v\n", cname, err)
	}
}
