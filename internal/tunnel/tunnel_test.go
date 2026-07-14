package tunnel

import (
	"bytes"
	"context"
	"errors"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"sync"
	"testing"
	"time"
)

func TestEstablishParsesEndpointAndCloses(t *testing.T) {
	command := shellScript(t, `
printf 'noise\nlistening at fake.test:4321\n'
exec sleep 30
`)
	tunnel, err := Establish(context.Background(), 1234, 0, Config{
		Command: command, PublicHost: "fake.test", StartupTimeout: time.Second,
	})
	if err != nil {
		t.Fatal(err)
	}
	info := tunnel.Info()
	if info.PublicHost != "fake.test" || info.PublicPort != 4321 || info.LocalPort != 1234 {
		t.Fatalf("tunnel endpoint = %#v", info)
	}
	tunnel.StartMonitor()
	if err := tunnel.Close(); err != nil {
		t.Fatal(err)
	}
	if err := tunnel.Close(); err != nil {
		t.Fatal("second Close:", err)
	}
}

func TestEstablishRecognizesPortConflict(t *testing.T) {
	command := shellScript(t, `
printf 'Error: address already in use\n' >&2
exec sleep 30
`)
	_, err := Establish(context.Background(), 1234, 4321, Config{
		Command: command, PublicHost: "fake.test", StartupTimeout: time.Second,
	})
	if !errors.Is(err, ErrPortInUse) {
		t.Fatalf("error = %v, want ErrPortInUse", err)
	}
}

func TestEstablishHasRealStartupTimeout(t *testing.T) {
	command := shellScript(t, `exec sleep 30`)
	started := time.Now()
	_, err := Establish(context.Background(), 1234, 0, Config{
		Command: command, PublicHost: "fake.test", StartupTimeout: 50 * time.Millisecond,
	})
	if !errors.Is(err, ErrTimeout) {
		t.Fatalf("error = %v, want ErrTimeout", err)
	}
	if elapsed := time.Since(started); elapsed > time.Second {
		t.Fatalf("startup timeout took %s", elapsed)
	}
}

func TestMonitorReconnectsAfterProcessExit(t *testing.T) {
	state := filepath.Join(t.TempDir(), "state")
	t.Setenv("FAKE_BORE_STATE", state)
	command := shellScript(t, `
if test -f "$FAKE_BORE_STATE"; then
  printf 'listening at fake.test:4321\n'
  exec sleep 30
fi
: > "$FAKE_BORE_STATE"
printf 'listening at fake.test:4321\n'
sleep 0.05
`)
	var logs lockedBuffer
	tunnel, err := Establish(context.Background(), 1234, 0, Config{
		Command: command, PublicHost: "fake.test", StartupTimeout: time.Second,
		Logger: &logs, Backoff: func(int) time.Duration { return time.Millisecond },
	})
	if err != nil {
		t.Fatal(err)
	}
	tunnel.StartMonitor()
	deadline := time.Now().Add(2 * time.Second)
	for !strings.Contains(logs.String(), "Tunnel reconnected: fake.test:4321") && time.Now().Before(deadline) {
		info := tunnel.Info()
		if info.PublicHost != "fake.test" || info.PublicPort != 4321 || info.LocalPort != 1234 {
			t.Fatalf("inconsistent tunnel snapshot during reconnect: %#v", info)
		}
		time.Sleep(5 * time.Millisecond)
	}
	if !strings.Contains(logs.String(), "Tunnel reconnected: fake.test:4321") {
		t.Fatalf("monitor did not reconnect; logs: %s", &logs)
	}
	if err := tunnel.Close(); err != nil {
		t.Fatal(err)
	}
}

func TestMissingBoreReturnsCleanError(t *testing.T) {
	_, err := Establish(context.Background(), 1234, 0, Config{
		Command: filepath.Join(t.TempDir(), "does-not-exist"), StartupTimeout: time.Second,
	})
	if err == nil || !strings.Contains(err.Error(), "start bore") {
		t.Fatalf("missing command error = %v", err)
	}
}

func shellScript(t *testing.T, body string) string {
	t.Helper()
	if runtime.GOOS == "windows" {
		t.Skip("fake bore scripts require a POSIX shell")
	}
	path := filepath.Join(t.TempDir(), "fake-bore")
	if err := os.WriteFile(path, []byte("#!/bin/sh\n"+body+"\n"), 0o700); err != nil {
		t.Fatal(err)
	}
	return path
}

type lockedBuffer struct {
	mu sync.Mutex
	bytes.Buffer
}

func (buffer *lockedBuffer) Write(data []byte) (int, error) {
	buffer.mu.Lock()
	defer buffer.mu.Unlock()
	return buffer.Buffer.Write(data)
}

func (buffer *lockedBuffer) String() string {
	buffer.mu.Lock()
	defer buffer.mu.Unlock()
	return buffer.Buffer.String()
}
