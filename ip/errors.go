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
	errorTruncated = errors.New("Truncated packet")
	errorInvalid   = errors.New("Invalid packet")
	errorChecksum  = errors.New("Invalid checksum")
)
