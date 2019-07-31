//
// checksum.go
//
// Copyright (c) 2019 Markku Rossi
//
// All rights reserved.
//

package ip

func Checksum(data []byte) uint16 {
	var sum uint32 = 0xffff
	var i int

	for i = 0; i < len(data); i += 2 {
		if i+1 < len(data) {
			sum += uint32(bo.Uint16(data[i:]))
		} else {
			sum += uint32(data[i])
		}
		if sum > 0xffff {
			sum -= 0xffff
		}
	}
	return uint16(^sum)
}
