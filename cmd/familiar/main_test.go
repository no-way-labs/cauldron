package main

import (
	"bytes"
	"os"
	"os/exec"
	"testing"
)

func TestCLIHelpVersionAndErrors(t *testing.T) {
	if code := run([]string{"--help"}); code != 0 {
		t.Fatalf("help exit = %d", code)
	}
	if code := run([]string{"--version"}); code != 0 {
		t.Fatalf("version exit = %d", code)
	}
	for _, args := range [][]string{{"--bogus"}, {"--api-port"}, {"--context", "0"}} {
		if code := run(args); code != 1 {
			t.Fatalf("run(%q) exit = %d", args, code)
		}
	}
}

func TestMissingAPIKeyFails(t *testing.T) {
	if os.Getenv("GO_WANT_FAMILIAR_HELPER") != "1" {
		return
	}
	os.Unsetenv("ANTHROPIC_API_KEY")
	os.Exit(run(nil))
}

func TestMissingAPIKeyExitCode(t *testing.T) {
	command := exec.Command(os.Args[0], "-test.run=TestMissingAPIKeyFails")
	command.Env = append(os.Environ(), "GO_WANT_FAMILIAR_HELPER=1", "ANTHROPIC_API_KEY=")
	var stderr bytes.Buffer
	command.Stderr = &stderr
	err := command.Run()
	exit, ok := err.(*exec.ExitError)
	if !ok || exit.ExitCode() != 1 {
		t.Fatalf("exit error = %v, stderr=%s", err, stderr.Bytes())
	}
}
