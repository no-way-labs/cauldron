package main

import (
	"bytes"
	"os"
	"os/exec"
	"strings"
	"testing"
)

func TestParseGlobsDropsEmptyTokens(t *testing.T) {
	got := parseGlobs("*.txt,,*.csv,")
	if len(got) != 2 || got[0] != "*.txt" || got[1] != "*.csv" {
		t.Fatalf("parseGlobs = %#v", got)
	}
}

func TestCLIContracts(t *testing.T) {
	tests := []struct {
		name       string
		args       []string
		exit       int
		stderrText string
	}{
		{name: "no_args", exit: 0, stderrText: "Usage: mitt <command>"},
		{name: "version", args: []string{"--version"}, exit: 0, stderrText: "mitt 0.0.0-dev\n"},
		{name: "help_quirk", args: []string{"--help"}, exit: 1, stderrText: "Unknown command: --help"},
		{name: "unknown_open_option", args: []string{"open", "--bogus"}, exit: 1, stderrText: "unknown option --bogus"},
		{name: "missing_value", args: []string{"open", "--password"}, exit: 1, stderrText: "--password requires a value"},
		{name: "empty_secret", args: []string{"send", "localhost:1", "--text", "x", "--password", ""}, exit: 1, stderrText: "requires a non-empty value"},
		{name: "missing_secret", args: []string{"send", "localhost:1", "--text", "x"}, exit: 1, stderrText: "MITT_PASSWORD"},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			exit, stdout, stderr := runMittHelper(t, test.args)
			if exit != test.exit {
				t.Fatalf("exit = %d, want %d; stderr:\n%s", exit, test.exit, stderr)
			}
			if stdout != "" {
				t.Fatalf("stdout = %q, want empty", stdout)
			}
			if test.name == "version" {
				if stderr != test.stderrText {
					t.Fatalf("stderr = %q, want %q", stderr, test.stderrText)
				}
			} else if !strings.Contains(stderr, test.stderrText) {
				t.Fatalf("stderr does not contain %q:\n%s", test.stderrText, stderr)
			}
		})
	}
}

func TestMittCLIHelper(t *testing.T) {
	if os.Getenv("GO_WANT_MITT_HELPER") != "1" {
		return
	}
	separator := 0
	for separator < len(os.Args) && os.Args[separator] != "--" {
		separator++
	}
	if separator == len(os.Args) {
		os.Exit(99)
	}
	os.Unsetenv("MITT_PASSWORD")
	os.Exit(run(os.Args[separator+1:]))
}

func runMittHelper(t *testing.T, args []string) (int, string, string) {
	t.Helper()
	commandArgs := []string{"-test.run=^TestMittCLIHelper$", "--"}
	commandArgs = append(commandArgs, args...)
	command := exec.Command(os.Args[0], commandArgs...)
	command.Env = append(os.Environ(), "GO_WANT_MITT_HELPER=1", "MITT_PASSWORD=")
	var stdout, stderr bytes.Buffer
	command.Stdout, command.Stderr = &stdout, &stderr
	err := command.Run()
	exit := 0
	if errorWithExit, ok := err.(*exec.ExitError); ok {
		exit = errorWithExit.ExitCode()
	} else if err != nil {
		t.Fatal(err)
	}
	return exit, stdout.String(), stderr.String()
}
