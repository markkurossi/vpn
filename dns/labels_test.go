//
// labels_test.go
//
// Copyright (c) 2019 Markku Rossi
//
// All rights reserved.
//

package dns

import (
	"testing"
)

func TestSuffix(t *testing.T) {
	label := Labels([]string{"adx", "adform", "net"})
	pattern := Labels([]string{"*", "adform", "net"})

	if !label.Match(pattern) {
		t.Errorf("Suffix match failed")
	}
}

func TestExact(t *testing.T) {
	label := Labels([]string{"ad", "markkurossi", "com"})
	if !label.Match(label) {
		t.Errorf("Exact match failed")
	}
}
