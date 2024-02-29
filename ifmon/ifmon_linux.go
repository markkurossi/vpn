//
// Copyright (c) 2024 Markku Rossi
//
// All rights reserved.
//

package ifmon

import "C"

import (
	"errors"
)

func platformCreate() (C.int, error) {
	return -1, errors.New("ifmon.platformCreate not implemented for linux")
}

func platformWait(fd C.int) error {
	return errors.New("ifmon.platformWait not implemented for linux")
}
