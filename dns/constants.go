//
// constants.go
//
// Copyright (c) 2019 Markku Rossi
//
// All rights reserved.
//

// Package dns provides types and primitives for parsing and creating
// DNS packets.
package dns

import (
	"fmt"
)

const (
	HeaderLen = 12
	FlagQR    = 0x8000
	FlagAA    = 0x0400
	FlagTC    = 0x0200
	FlagRD    = 0x0100
	FlagRA    = 0x0080
)

type ID uint16

func (id ID) String() string {
	return fmt.Sprintf("%04d", id)
}

type Opcode uint8

const (
	QUERY Opcode = iota
	IQUERY
	STATUS
)

func (oc Opcode) String() string {
	switch oc {
	case QUERY:
		return "QUERY"
	case IQUERY:
		return "IQUERY"
	case STATUS:
		return "STATUS"
	default:
		return fmt.Sprintf("{Opcode %d}", oc)
	}
}

type RCODE uint8

const (
	NoError RCODE = iota
	FormErr
	ServFail
	NXDomain
	NotImp
	Refused
	YXDomain
	YXRRSet
	NXRRSet
	NotAuth
	NotZone
	BADVERS
	BADSIG
	BADKEY
	BADTIME
	BADMODE
	BADNAME
	BADALG
	BADTRUNC
	BADCOOKIE
)

var rcodes = map[RCODE]string{
	NoError:   "No Error",
	FormErr:   "Format Error",
	ServFail:  "Server Failure",
	NXDomain:  "Non-Existent Domain",
	NotImp:    "Not Implemented",
	Refused:   "Query Refused",
	YXDomain:  "Name Exists when it should not",
	YXRRSet:   "RR Set Exists when it should not",
	NXRRSet:   "RR Set that should exist does not",
	NotAuth:   "Server Not Authoritative for zone",
	NotZone:   "Name not contained in zone",
	BADVERS:   "Bad OPT Version",
	BADSIG:    "TSIG Signature Failure",
	BADKEY:    "Key not recognized",
	BADTIME:   "Signature out of time window",
	BADMODE:   "Bad TKEY Mode",
	BADNAME:   "Duplicate key name",
	BADALG:    "Algorithm not supported",
	BADTRUNC:  "Bad Truncation",
	BADCOOKIE: "Bad/missing Server Cookie",
}

func (rc RCODE) String() string {
	val, ok := rcodes[rc]
	if ok {
		return val
	}
	return fmt.Sprintf("{RCODE %d}", rc)
}

type TYPE uint16

const (
	A TYPE = iota + 1
	NS
	MD
	MF
	CNAME
	SOA
	MB
	MG
	MR
	NULL
	WKS
	PTR
	HINFO
	MINFO
	MX
	TXT
	RP
	AFSDB
	X25
	ISDN
	RT
	NSAP
	NSAP_PTR
	SIG
	KEY
	PX
	GPOS
	AAAA
	LOC
	NXT
	EID
	NIMLOC
	SRV
	ATMA
	NAPTR
	KX
	CERT
	A6
	DNAME
	SINK
	OPT
	APL
	DS
	SSHFP
	IPSECKEY
	RRSIG
	NSEC
	DNSKEY
	DHCID
	NSEC3
	NSEC3PARAM
	TLSA
	SMIMEA
	_
	HIP
	NINFO
	RKEY
	TALINK
	CDS
	CDNSKEY
	OPENPGPKEY
	CSYNC
	ZONEMD
)

const (
	SPF TYPE = iota + 99
	UINFO
	UID
	GID
	UNSPEC
	NID
	L32
	L64
	LP
	EUI48
	EUI64
)

const (
	TKEY TYPE = iota + 249
	TSIG
	IXFR
	AXFR
	MAILB
	MAILA
	AllRecords
	URI
	CAA
	AVC
	DOA
	AMTRELAY

	TA  = 32768
	DLV = 32769
)

var types = map[TYPE]string{
	A:          "A",
	NS:         "NS",
	MD:         "MD",
	MF:         "MF",
	CNAME:      "CNAME",
	SOA:        "SOA",
	MB:         "MB",
	MG:         "MG",
	MR:         "MR",
	NULL:       "NULL",
	WKS:        "WKS",
	PTR:        "PTR",
	HINFO:      "HINFO",
	MINFO:      "MINFO",
	MX:         "MX",
	TXT:        "TXT",
	RP:         "RP",
	AFSDB:      "AFSDB",
	X25:        "X25",
	ISDN:       "ISDN",
	RT:         "RT",
	NSAP:       "NSAP",
	NSAP_PTR:   "NSAP-PTR",
	SIG:        "SIG",
	KEY:        "KEY",
	PX:         "PX",
	GPOS:       "GPOS",
	AAAA:       "AAAA",
	LOC:        "LOC",
	NXT:        "NXT",
	EID:        "EID",
	NIMLOC:     "NIMLOC",
	SRV:        "SRV",
	ATMA:       "ATMA",
	NAPTR:      "NAPTR",
	KX:         "KX",
	CERT:       "CERT",
	A6:         "A6",
	DNAME:      "DNAME",
	SINK:       "SINK",
	OPT:        "OPT",
	APL:        "APL",
	DS:         "DS",
	SSHFP:      "SSHFP",
	IPSECKEY:   "IPSECKEY",
	RRSIG:      "RRSIG",
	NSEC:       "NSEC",
	DNSKEY:     "DNSKEY",
	DHCID:      "DHCID",
	NSEC3:      "NSEC3",
	NSEC3PARAM: "NSEC3PARAM",
	TLSA:       "TLSA",
	SMIMEA:     "SMIMEA",
	HIP:        "HIP",
	NINFO:      "NINFO",
	RKEY:       "RKEY",
	TALINK:     "TALINK",
	CDS:        "CDS",
	CDNSKEY:    "CDNSKEY",
	OPENPGPKEY: "OPENPGPKEY",
	CSYNC:      "CSYNC",
	ZONEMD:     "ZONEMD",
	SPF:        "SPF",
	UINFO:      "UINFO",
	UID:        "UID",
	GID:        "GID",
	UNSPEC:     "UNSPEC",
	NID:        "NID",
	L32:        "L32",
	L64:        "L64",
	LP:         "LP",
	EUI48:      "EUI48",
	EUI64:      "EUI64",
	TKEY:       "TKEY",
	TSIG:       "TSIG",
	IXFR:       "IXFR",
	AXFR:       "AXFR",
	MAILB:      "MAILB",
	MAILA:      "MAILA",
	AllRecords: "*",
	URI:        "URI",
	CAA:        "CAA",
	AVC:        "AVC",
	DOA:        "DOA",
	AMTRELAY:   "AMTRELAY",
	TA:         "TA",
	DLV:        "DLV",
}

func (t TYPE) String() string {
	name, ok := types[t]
	if ok {
		return name
	}
	return fmt.Sprintf("{TYPE %d}", t)
}

type CLASS uint16

const (
	IN   CLASS = 1
	CH   CLASS = 3
	HS   CLASS = 4
	NONE CLASS = 254
	ANY  CLASS = 255
)

var classes = map[CLASS]string{
	IN:   "IN",
	CH:   "CH",
	HS:   "HS",
	NONE: "QCLASS NONE",
	ANY:  "QCLASS *",
}

func (c CLASS) String() string {
	name, ok := classes[c]
	if ok {
		return name
	}
	return fmt.Sprintf("{CLASS %d}", c)
}

type OptCode uint16

const (
	OptLLQ              OptCode = iota + 1 // RFC-sekar-dns-llq-06
	OptUL                                  // http://files.dns-sd.org/draft-sekar-dns-ul.txt
	OptNSID                                // RFC5001
	OptReserved                            // draft-cheshire-edns0-owner-option
	OptDAU                                 // RFC6975
	OptDHU                                 // RFC6975
	OptN3U                                 // RFC6975
	OptEDNSClientSubnet                    // RFC7871
	OptEDNSExpire                          // RFC7314
	OptCOOKIE                              // RFC7873
	OptEDNSTCPKeepalive                    // RFC7828
	OptPadding                             // RFC7830
	OptCHAIN                               // RFC7901
	OptEDNSKeyTag                          // RFC8145
	_
	OptEDNSClientTag //	draft-bellis-dnsop-edns-tags
	OptEDNSServerTag //	draft-bellis-dnsop-edns-tags

	OptDeviceID OptCode = 26946
)

var opts = map[OptCode]string{
	OptLLQ:              "LLQ",
	OptUL:               "UL",
	OptNSID:             "NSID",
	OptReserved:         "Reserved",
	OptDAU:              "DAU",
	OptDHU:              "DHU",
	OptN3U:              "N3U",
	OptEDNSClientSubnet: "edns-client-subnet",
	OptEDNSExpire:       "EDNS Expire",
	OptCOOKIE:           "COOKIE",
	OptEDNSTCPKeepalive: "edns-tcp-keepalive",
	OptPadding:          "Padding",
	OptCHAIN:            "CHAIN",
	OptEDNSKeyTag:       "edns-key-tag",
	OptEDNSClientTag:    "EDNS-Client-Tag",
	OptEDNSServerTag:    "EDNS-Server-Tag",
	OptDeviceID:         "DeviceID",
}

func (opt OptCode) String() string {
	name, ok := opts[opt]
	if ok {
		return name
	}
	return fmt.Sprintf("{OptCode %d}", opt)
}
