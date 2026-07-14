package main

import (
	"bufio"
	"bytes"
	"context"
	"errors"
	"io"
	"os"
	"os/exec"
	"strings"
	"testing"
)

func TestTopLevelCLIContracts(t *testing.T) {
	tests := []struct {
		name, contains string
		args           []string
		exit           int
	}{
		{name: "no_args", contains: "Usage: omen <command>", exit: 0},
		{name: "help", args: []string{"--help"}, contains: "Usage: omen <command>", exit: 0},
		{name: "version", args: []string{"--version"}, contains: "omen 0.0.0-dev\n", exit: 0},
		{name: "unknown", args: []string{"bogus"}, contains: "Unknown command: bogus", exit: 1},
		{name: "missing_question", args: []string{"host", "--local"}, contains: "question is required", exit: 1},
		{name: "roster_requires_identity", args: []string{"host", "?", "--roster", "x"}, contains: "OMEN_IDENTITY", exit: 1},
		{name: "missing_join_password", args: []string{"join", "localhost:1"}, contains: "OMEN_PASSWORD", exit: 1},
		{name: "empty_password", args: []string{"join", "localhost:1", "--password", ""}, contains: "requires a non-empty value", exit: 1},
		{name: "unknown_option", args: []string{"host", "?", "--bogus"}, contains: "unknown option --bogus", exit: 1},
		{name: "bad_max", args: []string{"host", "?", "--max-voters", "255"}, contains: "between 1 and 254", exit: 1},
		{name: "duplicate_options", args: []string{"host", "?", "--options", "a,a"}, contains: "duplicate option", exit: 1},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			exit, stdout, stderr := omenHelper(t, test.args)
			if exit != test.exit || stdout != "" || !strings.Contains(stderr, test.contains) {
				t.Fatalf("exit=%d stdout=%q stderr=%q; want exit=%d and %q", exit, stdout, stderr, test.exit, test.contains)
			}
		})
	}
}

func TestBoundedLineHandlingAndChoice(t *testing.T) {
	reader := bufio.NewReaderSize(strings.NewReader(strings.Repeat("x", 20)+"\n2\n"), 4)
	if line, err := readBoundedLine(reader, 8); line != "" || err != errLineTooLong {
		t.Fatalf("overlong line = %q, %v", line, err)
	}
	line, err := readBoundedLine(reader, 8)
	if err != nil || line != "2\n" {
		t.Fatalf("next line = %q, %v", line, err)
	}
	if choice, err := parseChoice(strings.TrimSpace(line), 2); err != nil || choice != 1 {
		t.Fatalf("choice = %d, %v", choice, err)
	}
}

func TestBoundedVoteInputHonorsCancellation(t *testing.T) {
	reader, writer := io.Pipe()
	buffered := bufio.NewReader(reader)
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	if _, err := readBoundedLineContext(ctx, buffered, 64); !errors.Is(err, context.Canceled) {
		t.Fatalf("canceled read error = %v", err)
	}
	_ = writer.Close()
	_ = reader.Close()
}

func TestParseOptions(t *testing.T) {
	options, err := parseOptions(true, " yes, , no ")
	if err != nil || len(options) != 2 || options[0] != "yes" || options[1] != "no" {
		t.Fatalf("options = %#v, %v", options, err)
	}
}

func TestOmenCLIHelper(t *testing.T) {
	if os.Getenv("GO_WANT_OMEN_HELPER") != "1" {
		return
	}
	separator := 0
	for separator < len(os.Args) && os.Args[separator] != "--" {
		separator++
	}
	if separator == len(os.Args) {
		os.Exit(99)
	}
	os.Unsetenv("OMEN_PASSWORD")
	os.Unsetenv("OMEN_IDENTITY")
	os.Exit(run(os.Args[separator+1:]))
}

func omenHelper(t *testing.T, args []string) (int, string, string) {
	t.Helper()
	commandArgs := append([]string{"-test.run=^TestOmenCLIHelper$", "--"}, args...)
	command := exec.Command(os.Args[0], commandArgs...)
	command.Env = append(os.Environ(), "GO_WANT_OMEN_HELPER=1", "OMEN_PASSWORD=", "OMEN_IDENTITY=")
	var stdout, stderr bytes.Buffer
	command.Stdout, command.Stderr = &stdout, &stderr
	err := command.Run()
	exit := 0
	if exitError, ok := err.(*exec.ExitError); ok {
		exit = exitError.ExitCode()
	} else if err != nil {
		t.Fatal(err)
	}
	return exit, stdout.String(), stderr.String()
}
