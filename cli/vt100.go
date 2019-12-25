//
// vt100.go
//
// Copyright (c) 2018, 2019 Markku Rossi
//
// All rights reserved.
//

package cli

import (
	"fmt"
	"io"
)

func VT100CursorForward(out io.Writer) error {
	_, err := out.Write([]byte{0x1b, '[', 'C'})
	return err
}

func VT100Backspace(out io.Writer) error {
	_, err := out.Write([]byte{0x08})
	return err
}

func VT100DeleteChar(out io.Writer) error {
	_, err := out.Write([]byte{0x1b, '[', 'P'})
	return err
}

func VT100EraseLineHead(out io.Writer) error {
	_, err := out.Write([]byte{0x1b, '[', '1', 'K'})
	return err
}

func VT100EraseLineTail(out io.Writer) error {
	_, err := out.Write([]byte{0x1b, '[', 'K'})
	return err
}

func VT100EraseLine(out io.Writer) error {
	_, err := out.Write([]byte{0x1b, '[', '2', 'K'})
	return err
}

func VT100EraseScreenHead(out io.Writer) error {
	_, err := out.Write([]byte{0x1b, '[', '1', 'J'})
	return err
}

func VT100EraseScreenTail(out io.Writer) error {
	_, err := out.Write([]byte{0x1b, '[', 'J'})
	return err
}

func VT100EraseScreen(out io.Writer) error {
	_, err := out.Write([]byte{0x1b, '[', '2', 'J'})
	return err
}

func VT100ReverseVideo(out io.Writer) error {
	_, err := out.Write([]byte{0x1b, '[', '7', 'm'})
	return err
}

func VT100TurnOffCharacterAttrs(out io.Writer) error {
	_, err := out.Write([]byte{0x1b, '[', 'm'})
	return err
}

func VT100MoveTo(out io.Writer, row, col int) error {
	_, err := out.Write([]byte(fmt.Sprintf("\x1b[%d;%dH", row, col)))
	return err
}

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
