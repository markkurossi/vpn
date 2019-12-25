//
// display.go
//
// Copyright (c) 2019 Markku Rossi
//
// All rights reserved.
//

package cli

import (
	"fmt"
	"io"
	"log"
	"os"
	"os/exec"
	"regexp"
	"sort"
	"strconv"
	"strings"

	"github.com/markkurossi/vpn/dns"
)

var (
	reSize  = regexp.MustCompilePOSIX(`^([[:digit:]]+)[[:space:]]+([[:digit:]]+)$`)
	blocked = make(map[string]int)
	queries = make(map[string]int)
)

func Init() {
	VT100ShowCursor(os.Stdout, false)
}

func Reset() {
	VT100ShowCursor(os.Stdout, true)
}

func Size() (int, int, error) {
	cmd := exec.Command("stty", "size")
	cmd.Stdin = os.Stdin
	output, err := cmd.Output()
	if err != nil {
		return 0, 0, err
	}
	m := reSize.FindStringSubmatch(string(output))
	if m == nil {
		return 0, 0, fmt.Errorf("could not get tty size")
	}
	h, err := strconv.Atoi(m[1])
	if err != nil {
		return 0, 0, err
	}
	w, err := strconv.Atoi(m[2])
	if err != nil {
		return 0, 0, err
	}
	return h, w, nil
}

func EventHandler(ch chan dns.Event) {
	height, width, err := Size()
	if err != nil {
		log.Printf("Failed to get screen size: %s", err)
		height = 24
		return
	}
	bHeight := (height - 2) / 2
	qHeight := height - bHeight - 2

	var countQueries, countBlocks int

	for event := range ch {
		label := event.Labels.String()

		switch event.Type {
		case dns.EventQuery:
			count := queries[label]
			count++
			queries[label] = count
			countQueries++

		case dns.EventBlock:
			count := blocked[label]
			count++
			blocked[label] = count
			countBlocks++
		}
		printStats(os.Stdout, width, bHeight, qHeight, blocked, queries,
			countBlocks, countQueries)
	}
}

func printStats(out io.Writer, w, bHeight, qHeight int, b, q map[string]int,
	countB, countQ int) {

	total := countB + countQ

	VT100EraseScreen(out)

	VT100MoveTo(out, 1, 0)
	statusLine(out, 1, w, fmt.Sprintf("Blocked %d/%d (%.0f%%)",
		countB, total, float64(countB)/float64(total)*100))
	printMap(out, w, 2, bHeight, b)

	statusLine(out, bHeight+2, w, fmt.Sprintf("Queries %d/%d (%.0f%%)",
		countQ, total, float64(countQ)/float64(total)*100))
	printMap(out, w, bHeight+3, qHeight, q)
}

func printMap(out io.Writer, w, row, height int, stats map[string]int) {
	var keys []string
	for k, _ := range stats {
		keys = append(keys, k)
	}
	sort.Slice(keys, func(i, j int) bool {
		if stats[keys[i]] == stats[keys[j]] {
			return strings.Compare(keys[i], keys[j]) < 0
		}
		return stats[keys[i]] > stats[keys[j]]
	})

	for i := 0; i < height; i++ {
		VT100MoveTo(out, row+i, 0)
		if i < len(keys) {
			key := keys[i]

			maxKeyLen := w - 3 - 6
			if maxKeyLen > 0 && len(key) > maxKeyLen {
				key = key[:maxKeyLen]
			}

			fmt.Fprintf(out, "%2d %s", i+1, key)
			VT100MoveTo(out, row+i, 1+w-5)
			fmt.Fprintf(out, "%5d", stats[keys[i]])
		}
	}
}

func statusLine(out io.Writer, row, width int, msg string) {
	VT100MoveTo(out, row, 0)
	VT100ReverseVideo(out)
	if 3+len(msg) > width {
		fmt.Fprintf(out, "%s", msg)
	} else {
		fmt.Fprintf(out, "--")
		fmt.Fprintf(out, " %s ", msg)
		for i := 0; i < width-4-len(msg); i++ {
			fmt.Fprintf(out, "-")
		}
	}
	VT100TurnOffCharacterAttrs(out)
}
