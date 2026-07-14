package main

import (
	"bytes"
	"strings"
	"testing"

	seanceapp "github.com/no-way-labs/cauldron/internal/seance"
)

func TestTerminalEditorAndConcurrentRedrawState(t *testing.T) {
	var output bytes.Buffer
	ui := newTerminalUI(&output)
	ui.setRaw(true)
	for _, value := range []byte("ac") {
		ui.processByte(value)
	}
	ui.processByte(27)
	ui.processByte('[')
	ui.processByte('D')
	ui.processByte('b')
	ui.event(seanceapp.Message{Timestamp: 60, Sender: "peer", Content: "hello", Type: "msg"})
	line, submitted, quit := ui.processByte('\n')
	if !submitted || quit || line != "abc" {
		t.Fatalf("submit = %q, %v, %v", line, submitted, quit)
	}
	if !strings.Contains(output.String(), "peer") || !strings.Contains(output.String(), "hello") {
		t.Fatalf("redraw output = %q", output.String())
	}
}

func TestTerminalControlKeysAndHelpers(t *testing.T) {
	ui := newTerminalUI(&bytes.Buffer{})
	ui.setRaw(true)
	for _, value := range []byte("abc") {
		ui.processByte(value)
	}
	ui.processByte(1)
	ui.processByte(27)
	ui.processByte('[')
	ui.processByte('3')
	ui.processByte('~')
	ui.processByte(5)
	ui.processByte(127)
	line, _, _ := ui.processByte('\n')
	if line != "b" {
		t.Fatalf("edited line = %q", line)
	}
	if formatTime(3660) != "01:01" || colorForNick("x") < 31 {
		t.Fatal("display helper mismatch")
	}
}
