//
// errors.go
//
// Copyright (c) 2019-2023 Markku Rossi
//
// All rights reserved.
//

package ip

import (
	"errors"
)

// IP errors.
var (
	ErrorTruncated = errors.New("Truncated packet")
	ErrorInvalid   = errors.New("Invalid packet")
	ErrorChecksum  = errors.New("Invalid checksum")
)
