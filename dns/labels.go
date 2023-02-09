//
// Copyright (c) 2019-2023 Markku Rossi
//
// All rights reserved.
//

package dns

import (
	"strings"
)

// Labels define DNS labels.
type Labels []string

// NewLabels creates new labels instance from the argument string.q
func NewLabels(name string) Labels {
	return strings.Split(name, ".")
}

func (l Labels) String() string {
	return strings.Join(l, ".")
}

// Match tests if the argument labels match this label instance.
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
