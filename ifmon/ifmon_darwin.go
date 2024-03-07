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
	"fmt"
	"log"
)

// Vendor codes.
const (
	KevAnyVendor int = iota
	KevVendorApple
)

// Layers of event source.
const (
	KevAnyClass C.u_int32_t = iota
	KevNetworkClass
	KevIokitClass
	KevSystemClass
	KevAppleshareClass
	KevFirewallClass
	KevIEEE80211Class
)

// Components within layer.
const (
	KevAnySubclass C.u_int32_t = iota
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
	KevInetNewAddr C.u_int32_t = iota + 1
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

var KevInetSubclassCodes = map[C.u_int32_t]string{
	KevInetNewAddr:       "KevInetNewAddr",
	KevInetChangedAddr:   "KevInetChangedAddr",
	KevInetAddrDeleted:   "KevInetAddrDeleted",
	KevInetSifdstaddr:    "KevInetSifdstaddr",
	KevInetSifbrdaddr:    "KevInetSifbrdaddr",
	KevInetSifnetmask:    "KevInetSifnetmask",
	KevInetArpcollision:  "KevInetArpcollision",
	KevInetPortinuse:     "KevInetPortinuse",
	KevInetArprtrfailure: "KevInetArprtrfailure",
	KevInetArprtralive:   "KevInetArprtralive",
}

func KevInetSubclassCodeString(code C.u_int32_t) string {
	name, ok := KevInetSubclassCodes[code]
	if ok {
		return name
	}
	return fmt.Sprintf("{KevInetSubclassCode %d}", code)
}

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
	KevInet6NewUserAddr = iota + 1
	// Address changed event (future).
	KevInet6ChangedAddr
	// IPv6 address was deleted.
	KevInet6AddrDeleted
	// Autoconf LL address appeared.
	KevInet6NewLlAddr
	// Autoconf address has appeared.
	KevInet6NewRtadvAddr
	// Default router detected.
	KevInet6Defrouter
	// Asking for the NAT64-prefix.
	KevInet6RequestNat64Prefix
)

var KevInet6SubclassCodes = map[C.u_int32_t]string{
	KevInet6NewUserAddr:        "KevInet6NewUserAddr",
	KevInet6ChangedAddr:        "KevInet6ChangedAddr",
	KevInet6AddrDeleted:        "KevInet6AddrDeleted",
	KevInet6NewLlAddr:          "KevInet6NewLlAddr",
	KevInet6NewRtadvAddr:       "KevInet6NewRtadvAddr",
	KevInet6Defrouter:          "KevInet6Defrouter",
	KevInet6RequestNat64Prefix: "KevInet6RequestNat64Prefix",
}

func KevInet6SubclassCodeString(code C.u_int32_t) string {
	name, ok := KevInet6SubclassCodes[code]
	if ok {
		return name
	}
	return fmt.Sprintf("{KevInet6SubclassCode %d}", code)
}

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

	for {
		ret := C.ifmon_wait(fd, &cls, &subcls, &code, &errno)
		if ret < 0 {
			return errors.New(C.GoString(C.strerror(errno)))
		}
		if cls != KevNetworkClass {
			continue
		}
		switch subcls {
		case KevInetSubclass:
			log.Printf("inet:  code=%v", KevInetSubclassCodeString(code))
			switch code {
			case KevInetNewAddr, KevInetChangedAddr:
				return nil
			}
		case KevInet6Subclass:
			log.Printf("inet6: code=%v", KevInet6SubclassCodeString(code))
			switch code {
			case KevInet6NewUserAddr, KevInet6ChangedAddr:
				return nil
			}
		default:
			continue
		}
	}

	return nil
}
