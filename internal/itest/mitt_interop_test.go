package itest

import (
	"bufio"
	"bytes"
	"errors"
	"io"
	"os"
	"os/exec"
	"path/filepath"
	"strconv"
	"strings"
	"sync"
	"testing"
	"time"
)

// TestMittZigGoInterop is opt-in because it requires two prebuilt binaries:
//
//	CAULDRON_ZIG_MITT=zig-out/bin/mitt CAULDRON_GO_MITT=/tmp/go-mitt go test ./internal/itest
func TestMittZigGoInterop(t *testing.T) {
	zig := os.Getenv("CAULDRON_ZIG_MITT")
	goBinary := os.Getenv("CAULDRON_GO_MITT")
	if zig == "" || goBinary == "" {
		t.Skip("set CAULDRON_ZIG_MITT and CAULDRON_GO_MITT to run live interop")
	}
	for _, test := range []struct {
		name, sender, receiver string
	}{
		{name: "zig_sender_go_receiver", sender: zig, receiver: goBinary},
		{name: "go_sender_zig_receiver", sender: goBinary, receiver: zig},
	} {
		t.Run(test.name, func(t *testing.T) {
			runMittDirection(t, test.sender, test.receiver)
		})
	}
}

func runMittDirection(t *testing.T, senderPath, receiverPath string) {
	t.Helper()
	destination := t.TempDir()
	receiver := startMittReceiver(t, receiverPath, destination)
	defer receiver.stop(t)
	target := "localhost:" + strconv.Itoa(receiver.port)

	runMittSender(t, 0, nil, senderPath, "send", target, "--text", "hello", "--password", "interop-pass")
	file := filepath.Join(t.TempDir(), "payload.txt")
	if err := os.WriteFile(file, []byte("file-body"), 0o600); err != nil {
		t.Fatal(err)
	}
	runMittSender(t, 0, nil, senderPath, "send", target, file, "--password", "interop-pass")
	runMittSender(t, 0, strings.NewReader("stdin-body"), senderPath, "send", target, "-", "--password", "interop-pass")

	rejected := filepath.Join(t.TempDir(), "bad.exe")
	if err := os.WriteFile(rejected, []byte("bad"), 0o600); err != nil {
		t.Fatal(err)
	}
	runMittSender(t, 2, nil, senderPath, "send", target, rejected, "--password", "interop-pass")
	runMittSender(t, 2, nil, senderPath, "send", target, "--text", "thirteen-byte!", "--password", "interop-pass")
	runMittSender(t, 2, nil, senderPath, "send", target, "--text", "wrong-key", "--password", "not-the-password")

	for name, want := range map[string]string{
		"text.txt": "hello", "payload.txt": "file-body", "stdin": "stdin-body",
	} {
		data, err := os.ReadFile(filepath.Join(destination, name))
		if err != nil || string(data) != want {
			t.Fatalf("received %s = %q, %v; receiver logs:\n%s", name, data, err, receiver.logs.String())
		}
	}
	if _, err := os.Stat(filepath.Join(destination, "bad.exe")); !os.IsNotExist(err) {
		t.Fatalf("rejected file was saved: %v", err)
	}
}

type mittReceiver struct {
	cmd  *exec.Cmd
	port int
	wait chan error
	logs lockedBuffer
}

func startMittReceiver(t *testing.T, binary, destination string) *mittReceiver {
	t.Helper()
	receiver := &mittReceiver{wait: make(chan error, 1)}
	receiver.cmd = exec.Command(binary, "open", "--local", "--quiet", "--dir", destination,
		"--reject", "*.exe", "--max-size", "12", "--password", "interop-pass")
	receiver.cmd.Stdout = io.Discard
	stderr, err := receiver.cmd.StderrPipe()
	if err != nil {
		t.Fatal(err)
	}
	if err := receiver.cmd.Start(); err != nil {
		t.Fatal(err)
	}
	port := make(chan int, 1)
	go func() {
		scanner := bufio.NewScanner(stderr)
		for scanner.Scan() {
			line := scanner.Text()
			receiver.logs.appendLine(line)
			if strings.HasPrefix(line, "Local: localhost:") {
				parsed, parseErr := strconv.Atoi(strings.TrimPrefix(line, "Local: localhost:"))
				if parseErr == nil {
					select {
					case port <- parsed:
					default:
					}
				}
			}
		}
	}()
	go func() { receiver.wait <- receiver.cmd.Wait() }()
	select {
	case receiver.port = <-port:
		return receiver
	case err := <-receiver.wait:
		t.Fatalf("receiver exited before listening: %v\n%s", err, receiver.logs.String())
	case <-time.After(10 * time.Second):
		receiver.stop(t)
		t.Fatalf("receiver did not report a port:\n%s", receiver.logs.String())
	}
	return nil
}

func (receiver *mittReceiver) stop(t *testing.T) {
	t.Helper()
	if receiver.cmd.Process == nil {
		return
	}
	_ = receiver.cmd.Process.Signal(os.Interrupt)
	select {
	case <-receiver.wait:
	case <-time.After(2 * time.Second):
		_ = receiver.cmd.Process.Kill()
		<-receiver.wait
	}
	receiver.cmd.Process = nil
}

func runMittSender(t *testing.T, wantExit int, stdin io.Reader, binary string, args ...string) {
	t.Helper()
	command := exec.Command(binary, args...)
	command.Stdin = stdin
	var output bytes.Buffer
	command.Stdout, command.Stderr = &output, &output
	err := command.Run()
	exit := 0
	if err != nil {
		var exitError *exec.ExitError
		if !errors.As(err, &exitError) {
			t.Fatalf("run %s: %v", binary, err)
		}
		exit = exitError.ExitCode()
	}
	if exit != wantExit {
		t.Fatalf("sender exit = %d, want %d; command %s %s; output:\n%s",
			exit, wantExit, binary, strings.Join(args, " "), &output)
	}
	if wantExit == 0 && !strings.Contains(output.String(), "Delivered.") {
		t.Fatalf("successful sender omitted Delivered.; output:\n%s", &output)
	}
}

type lockedBuffer struct {
	mu sync.Mutex
	bytes.Buffer
}

func (buffer *lockedBuffer) appendLine(line string) {
	buffer.mu.Lock()
	defer buffer.mu.Unlock()
	buffer.Buffer.WriteString(line)
	buffer.Buffer.WriteByte('\n')
}

func (buffer *lockedBuffer) String() string {
	buffer.mu.Lock()
	defer buffer.mu.Unlock()
	return buffer.Buffer.String()
}
