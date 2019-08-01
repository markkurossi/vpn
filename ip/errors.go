//
// errors.go
//
// Copyright (c) 2019 Markku Rossi
//
// All rights reserved.
//

package ip

import (
	"errors"
)

var (
	ErrorTruncated = errors.New("Truncated packet")
	ErrorInvalid   = errors.New("Invalid packet")
	ErrorChecksum  = errors.New("Invalid checksum")
)
