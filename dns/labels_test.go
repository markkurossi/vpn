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

func TestHeadGlob(t *testing.T) {
	label := Labels([]string{"ads", "markkurossi", "com"})
	pattern := Labels([]string{"ads", "*"})
	if !label.Match(pattern) {
		t.Errorf("Head glob match failed")
	}
}

func TestNonEmptyGlob(t *testing.T) {
	label := Labels([]string{"ads", "markkurossi", "com"})
	pattern := Labels([]string{"*", "markkurossi", "com"})
	if !label.Match(pattern) {
		t.Errorf("Glob match failed")
	}
	label = Labels([]string{"web", "hb", "ad", "cpe", "dotomi", "com"})
	pattern = Labels([]string{"*", "ad", "*"})
	if !label.Match(pattern) {
		t.Errorf("Glob match 2 failed")
	}
}

func TestEmptyGlob(t *testing.T) {
	label := Labels([]string{"markkurossi", "com"})
	pattern := Labels([]string{"*", "markkurossi", "com"})
	if label.Match(pattern) {
		t.Errorf("Empty glob match failed")
	}
	pattern = Labels([]string{"**", "markkurossi", "com"})
	if !label.Match(pattern) {
		t.Errorf("Empty glob match failed")
	}
}
