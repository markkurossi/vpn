//
// Copyright (c) 2024 Markku Rossi
//
// All rights reserved.
//

package ifmon

// #include "ifmon_darwin.h"
import "C"

import (
	"errors"
	"log"
)

// Vendor codes.
const (
	KevAnyVendor int = iota
	KevVendorApple
)

// Layers of event source.
const (
	KevAnyClass int = iota
	KevNetworkClass
	KevIokitClass
	KevSystemClass
	KevAppleshareClass
	KevFirewallClass
	KevIEEE80211Class
)

// Components within layer.
const (
	KevAnySubclass int = iota
	KevInetSubclass
	KevDlSubclass
	_
	_
	_
	KevInet6Subclass
)

// KevInetSubclass event codes.
const (
	// Userland configured IP address.
	KevInetNewAddr = iota + 1
	// Address changed event.
	KevInetChangedAddr
	// IPv6 address was deleted.
	KevInetAddrDeleted
	// Dest. address was set.
	KevInetSifdstaddr
	// Broadcast address was set.
	KevInetSifbrdaddr
	// Netmask was set.
	KevInetSifnetmask
	// ARP collision detected.
	KevInetArpcollision
	// use keninportinuse.
	KevInetPortinuse
	// ARP resolution failed for router.
	KevInetArprtrfailure
	// ARP resolution succeeded for route.
	KevInetArprtralive
)

// KevDlSubclass event codes.
const (
	KevDlSifflags = iota + 1
	KevDlSifmetrics
	KevDlSifmtu
	KevDlSifphys
	KevDlSifmedia
	KevDlSifgeneric
	KevDlAddmulti
	KevDlDelmulti
	KevDlIfAttached
	KevDlIfDetaching
	KevDlIfDetached
	KevDlLinkOff
	KevDlLinkOn
	KevDlProtoAttached
	KevDlProtoDetached
	KevDlLinkAddressChanged
	KevDlWakeflagsChanged
	KevDlIfIdleRouteRefcnt
	KevDlIfcapChanged
	KevDlLinkQualityMetricChanged
	KevDlNodePresence
	KevDlNodeAbsence
	KevDlMasterElected
	KevDlIssues
	KevDlIfdelegateChanged
	KevDlAwdlRestricted
	KevDlAwdlUnrestricted
	KevDlRrcStateChanged
	KevDlQosModeChanged
	KevDlLowPowerModeChanged
)

// KevInet6Subclass event codes.
const (
	// Userland configured IPv6 address.
	KevInet6NewUserADDR = iota + 1
	// Address changed event (future).
	KevInet6ChangedADDR
	// IPv6 address was deleted.
	KevInet6AddrDELETED
	// Autoconf LL address appeared.
	KevInet6NewLlADDR
	// Autoconf address has appeared.
	KevInet6NewRtadvADDR
	// Default router detected.
	KevInet6DEFROUTER
	// Asking for the NAT64-prefix.
	KevInet6RequestNat64Prefix
)

func platformCreate() (C.int, error) {
	var errno C.int

	ret := C.ifmon_create(&errno)
	if ret < 0 {
		return -1, errors.New(C.GoString(C.strerror(errno)))
	}

	return ret, nil
}

func platformWait(fd C.int) error {
	var cls, subcls, code C.u_int32_t
	var errno C.int

	ret := C.ifmon_wait(fd, &cls, &subcls, &code, &errno)
	if ret < 0 {
		return errors.New(C.GoString(C.strerror(errno)))
	}

	log.Printf("cls=%v, subcls=%v, code=%v", cls, subcls, code)

	return nil
}
