//
// Copyright (c) 2019-2020 Markku Rossi
//
// All rights reserved.
//

package dns

import (
	"strings"
)

type Labels []string

func NewLabels(name string) Labels {
	return strings.Split(name, ".")
}

func (l Labels) String() string {
	return strings.Join(l, ".")
}

func (l Labels) Match(o Labels) bool {
	return glob(l, o)
}

func glob(value, pattern []string) bool {
	for {
		if len(pattern) == 0 {
			if len(value) == 0 {
				return true
			}
			return false
		} else if len(value) == 0 {
			return false
		}
		switch pattern[0] {
		case "*":
			for i := 1; i <= len(value); i++ {
				if glob(value[i:], pattern[1:]) {
					return true
				}
			}
			return false

		case "**":
			for i := 0; i <= len(value); i++ {
				if glob(value[i:], pattern[1:]) {
					return true
				}
			}
			return false

		default:
			if pattern[0] != value[0] {
				return false
			}
		}
		pattern = pattern[1:]
		value = value[1:]
	}
}
