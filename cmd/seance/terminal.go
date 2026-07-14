package main

import (
	"fmt"
	"io"
	"sync"

	seanceapp "github.com/no-way-labs/cauldron/internal/seance"
)

const inputLimit = 4096

type terminalUI struct {
	out io.Writer
	mu  sync.Mutex

	raw    bool
	input  []byte
	cursor int
	escape int
	prompt string
}

func newTerminalUI(output io.Writer) *terminalUI {
	return &terminalUI{out: output, prompt: "\x1b[38;5;141m› \x1b[0m"}
}

func (ui *terminalUI) setRaw(raw bool) {
	ui.mu.Lock()
	defer ui.mu.Unlock()
	ui.raw = raw
	if raw {
		fmt.Fprint(ui.out, ui.prompt)
	}
}

func (ui *terminalUI) event(message seanceapp.Message) {
	ui.mu.Lock()
	defer ui.mu.Unlock()
	ui.clearInputLocked()
	switch message.Type {
	case "msg":
		fmt.Fprintf(ui.out, "\x1b[90m[%s]\x1b[0m \x1b[%dm%s\x1b[0m: %s\n",
			formatTime(message.Timestamp), colorForNick(message.Sender), message.Sender, message.Content)
	case "join", "leave", "announce":
		fmt.Fprintf(ui.out, "\x1b[90m\x1b[3m[%s] * %s\x1b[0m\n", formatTime(message.Timestamp), message.Content)
	case "nick_list":
		peers := parseDisplayedPeers(message.Content)
		fmt.Fprintf(ui.out, "\x1b[90m--- participants (%d) ---\x1b[0m\n", len(peers))
		for _, peer := range peers {
			fmt.Fprintf(ui.out, "  \x1b[%dm%s\x1b[0m\n", colorForNick(peer), peer)
		}
		fmt.Fprintln(ui.out, "\x1b[90m-----------------------\x1b[0m")
	}
	ui.restoreInputLocked()
}

func (ui *terminalUI) processByte(value byte) (line string, submitted, quit bool) {
	ui.mu.Lock()
	defer ui.mu.Unlock()
	if ui.escape != 0 {
		switch ui.escape {
		case 1:
			if value == '[' {
				ui.escape = 2
			} else {
				ui.escape = 0
			}
		case 2:
			ui.escape = 0
			switch value {
			case 'D':
				ui.moveLeftLocked()
			case 'C':
				ui.moveRightLocked()
			case 'H':
				ui.homeLocked()
			case 'F':
				ui.endLocked()
			case '3':
				ui.escape = 3
			}
		case 3:
			ui.escape = 0
			if value == '~' {
				ui.deleteLocked()
			}
		}
		return "", false, false
	}
	switch value {
	case 3, 4:
		return "", false, true
	case '\r', '\n':
		line = string(ui.input)
		ui.input = ui.input[:0]
		ui.cursor = 0
		fmt.Fprint(ui.out, "\r\x1b[2K")
		return line, true, line == "/quit"
	case 127, 8:
		ui.backspaceLocked()
	case 21:
		ui.input = ui.input[:0]
		ui.cursor = 0
		fmt.Fprint(ui.out, "\r\x1b[2K"+ui.prompt)
	case 1:
		ui.homeLocked()
	case 5:
		ui.endLocked()
	case 27:
		ui.escape = 1
	default:
		if value >= 32 && len(ui.input) < inputLimit {
			ui.insertLocked(value)
		}
	}
	return "", false, false
}

func (ui *terminalUI) insertLocked(value byte) {
	ui.input = append(ui.input, 0)
	copy(ui.input[ui.cursor+1:], ui.input[ui.cursor:len(ui.input)-1])
	ui.input[ui.cursor] = value
	ui.cursor++
	fmt.Fprint(ui.out, string(ui.input[ui.cursor-1:]))
	if back := len(ui.input) - ui.cursor; back > 0 {
		fmt.Fprintf(ui.out, "\x1b[%dD", back)
	}
}

func (ui *terminalUI) backspaceLocked() {
	if ui.cursor == 0 {
		return
	}
	copy(ui.input[ui.cursor-1:], ui.input[ui.cursor:])
	ui.input = ui.input[:len(ui.input)-1]
	ui.cursor--
	fmt.Fprintf(ui.out, "\x08%s ", ui.input[ui.cursor:])
	fmt.Fprintf(ui.out, "\x1b[%dD", len(ui.input)-ui.cursor+1)
}

func (ui *terminalUI) deleteLocked() {
	if ui.cursor >= len(ui.input) {
		return
	}
	copy(ui.input[ui.cursor:], ui.input[ui.cursor+1:])
	ui.input = ui.input[:len(ui.input)-1]
	fmt.Fprintf(ui.out, "%s ", ui.input[ui.cursor:])
	fmt.Fprintf(ui.out, "\x1b[%dD", len(ui.input)-ui.cursor+1)
}

func (ui *terminalUI) moveLeftLocked() {
	if ui.cursor > 0 {
		ui.cursor--
		fmt.Fprint(ui.out, "\x1b[D")
	}
}

func (ui *terminalUI) moveRightLocked() {
	if ui.cursor < len(ui.input) {
		ui.cursor++
		fmt.Fprint(ui.out, "\x1b[C")
	}
}

func (ui *terminalUI) homeLocked() {
	if ui.cursor > 0 {
		fmt.Fprintf(ui.out, "\x1b[%dD", ui.cursor)
		ui.cursor = 0
	}
}

func (ui *terminalUI) endLocked() {
	if ui.cursor < len(ui.input) {
		fmt.Fprintf(ui.out, "\x1b[%dC", len(ui.input)-ui.cursor)
		ui.cursor = len(ui.input)
	}
}

func (ui *terminalUI) clearInputLocked() {
	if ui.raw {
		fmt.Fprint(ui.out, "\r\x1b[2K")
	}
}

func (ui *terminalUI) restoreInputLocked() {
	if !ui.raw {
		return
	}
	fmt.Fprint(ui.out, ui.prompt)
	fmt.Fprint(ui.out, string(ui.input))
	if back := len(ui.input) - ui.cursor; back > 0 {
		fmt.Fprintf(ui.out, "\x1b[%dD", back)
	}
}

func formatTime(timestamp uint64) string {
	seconds := timestamp % 86400
	return fmt.Sprintf("%02d:%02d", seconds/3600, (seconds%3600)/60)
}

func colorForNick(nick string) int {
	colors := [...]int{31, 32, 33, 34, 35, 36, 91, 92, 93, 94, 95, 96}
	var hash uint32
	for _, value := range []byte(nick) {
		hash = hash*31 + uint32(value)
	}
	return colors[hash%uint32(len(colors))]
}

func parseDisplayedPeers(content string) []string {
	parts := make([]string, 0)
	start := 0
	for index := 0; index <= len(content); index++ {
		if index == len(content) || content[index] == '\n' {
			if index > start {
				parts = append(parts, content[start:index])
			}
			start = index + 1
		}
	}
	return parts
}
