//
// vt100.go
//
// Copyright (c) 2018-2023 Markku Rossi
//
// All rights reserved.
//

package cli

import (
	"fmt"
	"io"
)

// VT100CursorForward moves cursor right.
func VT100CursorForward(out io.Writer) error {
	_, err := out.Write([]byte{0x1b, '[', 'C'})
	return err
}

// VT100Backspace deletes character left of the cursor.
func VT100Backspace(out io.Writer) error {
	_, err := out.Write([]byte{0x08})
	return err
}

// VT100DeleteChar deletes character at the cursor position.
func VT100DeleteChar(out io.Writer) error {
	_, err := out.Write([]byte{0x1b, '[', 'P'})
	return err
}

// VT100EraseLineHead clears the line from the beginning of the line
// to the cursor position.
func VT100EraseLineHead(out io.Writer) error {
	_, err := out.Write([]byte{0x1b, '[', '1', 'K'})
	return err
}

// VT100EraseLineTail clears line from the cursor position to the end
// of line.
func VT100EraseLineTail(out io.Writer) error {
	_, err := out.Write([]byte{0x1b, '[', 'K'})
	return err
}

// VT100EraseLine clears the current line.
func VT100EraseLine(out io.Writer) error {
	_, err := out.Write([]byte{0x1b, '[', '2', 'K'})
	return err
}

// VT100EraseScreenHead clears the screen from the beginning of the
// display to the cursor position.
func VT100EraseScreenHead(out io.Writer) error {
	_, err := out.Write([]byte{0x1b, '[', '1', 'J'})
	return err
}

// VT100EraseScreenTail clears screen from the cursor position to the
// end of display.
func VT100EraseScreenTail(out io.Writer) error {
	_, err := out.Write([]byte{0x1b, '[', 'J'})
	return err
}

// VT100EraseScreen clears screen.
func VT100EraseScreen(out io.Writer) error {
	_, err := out.Write([]byte{0x1b, '[', '2', 'J'})
	return err
}

// VT100ReverseVideo turns on reverse display.
func VT100ReverseVideo(out io.Writer) error {
	_, err := out.Write([]byte{0x1b, '[', '7', 'm'})
	return err
}

// VT100TurnOffCharacterAttrs clears character attributes.
func VT100TurnOffCharacterAttrs(out io.Writer) error {
	_, err := out.Write([]byte{0x1b, '[', 'm'})
	return err
}

// VT100MoveTo moves cursor to the specivied row and column.
func VT100MoveTo(out io.Writer, row, col int) error {
	_, err := out.Write([]byte(fmt.Sprintf("\x1b[%d;%dH", row, col)))
	return err
}

// VT100ShowCursor controls if cursor is visible or not.
func VT100ShowCursor(out io.Writer, show bool) error {
	data := []byte{0x1b, '[', '?', '2', '5'}
	if show {
		data = append(data, 'h')
	} else {
		data = append(data, 'l')
	}
	_, err := out.Write(data)
	return err
}
