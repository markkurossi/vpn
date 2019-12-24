//
// tunnel.go
//
// Copyright (c) 2019 Markku Rossi
//
// All rights reserved.
//

package tun

// #include "tunnel.h"
import "C"

import (
	"errors"
	"unsafe"
)

const (
	DefaultClientIP = "192.168.192.1"   // LocalIP
	DefaultServerIP = "192.168.192.254" // RemoteIP
)

// EXT_IP is the VPN server address
// EXT_GW_IP is the default gw

type Config struct {
	Iface     string
	LocalIP   string
	RemoteIP  string
	LocalIP6  string
	RemoteIP6 string
	ServerIP  string
	GatewayIP string
}

type Tunnel struct {
	fd   C.int
	Name string
}

func Create() (*Tunnel, error) {
	var namePtr *C.char
	var errno C.int

	ret := C.tun_create(&namePtr, &errno)
	if ret < 0 {
		return nil, errors.New(C.GoString(C.strerror(errno)))
	}

	name := C.GoString(namePtr)
	C.free(unsafe.Pointer(namePtr))

	return &Tunnel{
		fd:   ret,
		Name: name,
	}, nil
}

func (t *Tunnel) String() string {
	return t.Name
}

func (t *Tunnel) Read() ([]byte, error) {
	buf := C.malloc(1500)
	var errno C.int

	len := C.tun_read(t.fd, buf, 1500, &errno)
	if len < 0 {
		return nil, errors.New(C.GoString(C.strerror(errno)))
	}

	arr := C.GoBytes(buf, C.int(len))
	C.free(unsafe.Pointer(buf))

	return arr, nil
}

func (t *Tunnel) Write(data []byte) (int, error) {
	var errno C.int

	buf := C.CBytes(data)
	n := C.tun_write(t.fd, buf, C.ulong(len(data)), &errno)
	C.free(unsafe.Pointer(buf))

	if n < 0 {
		return 0, errors.New(C.GoString(C.strerror(errno)))
	}

	return int(n), nil
}
