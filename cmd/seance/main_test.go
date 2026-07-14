package main

import (
	"bytes"
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
		{name: "no_args", contains: "Usage: seance <command>", exit: 0},
		{name: "help_is_unknown", args: []string{"--help"}, contains: "Unknown command: --help", exit: 1},
		{name: "version", args: []string{"--version"}, contains: "seance 0.0.0-dev\n", exit: 0},
		{name: "unknown", args: []string{"bogus"}, contains: "Unknown command: bogus", exit: 1},
		{name: "missing_join_password", args: []string{"join", "localhost:1"}, contains: "SEANCE_PASSWORD", exit: 1},
		{name: "empty_password", args: []string{"join", "localhost:1", "--password", ""}, contains: "requires a non-empty value", exit: 1},
		{name: "unknown_option", args: []string{"host", "--bogus"}, contains: "unknown option --bogus", exit: 1},
		{name: "bad_max", args: []string{"host", "--max-peers", "0"}, contains: "between 1 and 255", exit: 1},
		{name: "bad_api_port", args: []string{"join", "localhost:1", "--password", "x", "--api-port", "0"}, contains: "between 1 and 65535", exit: 1},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			exit, stdout, stderr := seanceHelper(t, test.args)
			if exit != test.exit || stdout != "" || !strings.Contains(stderr, test.contains) {
				t.Fatalf("exit=%d stdout=%q stderr=%q; want exit=%d and %q", exit, stdout, stderr, test.exit, test.contains)
			}
		})
	}
}

func TestBoundedLinesDropsOversizedInput(t *testing.T) {
	input := strings.NewReader(strings.Repeat("x", 20) + "\nhello\n")
	var got []string
	for line := range boundedLines(input, 8) {
		got = append(got, line)
	}
	if len(got) != 1 || got[0] != "hello\n" {
		t.Fatalf("lines = %#v", got)
	}
}

func TestSeanceCLIHelper(t *testing.T) {
	if os.Getenv("GO_WANT_SEANCE_HELPER") != "1" {
		return
	}
	separator := 0
	for separator < len(os.Args) && os.Args[separator] != "--" {
		separator++
	}
	if separator == len(os.Args) {
		os.Exit(99)
	}
	os.Unsetenv("SEANCE_PASSWORD")
	os.Exit(run(os.Args[separator+1:]))
}

func seanceHelper(t *testing.T, args []string) (int, string, string) {
	t.Helper()
	commandArgs := append([]string{"-test.run=^TestSeanceCLIHelper$", "--"}, args...)
	command := exec.Command(os.Args[0], commandArgs...)
	command.Env = append(os.Environ(), "GO_WANT_SEANCE_HELPER=1", "SEANCE_PASSWORD=")
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
