//
// Copyright (c) 2024 Markku Rossi
//
// All rights reserved.
//

package ifmon

import "C"

// Listener implements network interface change notification listener.
type Listener struct {
	fd C.int
}

// Create creates a new network interface change notification
// listener.
func Create() (*Listener, error) {
	fd, err := platformCreate()
	if err != nil {
		return nil, err
	}
	return &Listener{
		fd: fd,
	}, nil
}

// Wait waits for network interface changes.
func (l *Listener) Wait() error {
	return platformWait(l.fd)
}
