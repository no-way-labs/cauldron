package mitt

import (
	"bytes"
	"context"
	"encoding/binary"
	"io"
	"net"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/no-way-labs/cauldron/internal/secretbox"
)

func TestSanitizeFilename(t *testing.T) {
	tests := map[string]string{
		"normal.txt":         "normal.txt",
		"../../etc/passwd":   "passwd",
		`windows\path\x.csv`: "x.csv",
		".hidden":            "",
		"two..dots":          "",
		"bad name.txt":       "",
		"":                   "",
	}
	for input, want := range tests {
		if got := sanitizeFilename(input); got != want {
			t.Errorf("sanitizeFilename(%q) = %q, want %q", input, got, want)
		}
	}
}

func FuzzSanitizeFilename(f *testing.F) {
	for _, seed := range []string{"../../etc/passwd", "normal.txt", `.hidden`, "weird\x00name?.txt"} {
		f.Add(seed)
	}
	f.Fuzz(func(t *testing.T, input string) {
		output := sanitizeFilename(input)
		if output == "" {
			return
		}
		if output[0] == '.' || strings.Contains(output, "..") {
			t.Fatalf("unsafe output %q", output)
		}
		for _, character := range []byte(output) {
			if !strings.ContainsRune("abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789-_.", rune(character)) {
				t.Fatalf("unsafe byte in %q", output)
			}
		}
	})
}

func TestFilterPrecedence(t *testing.T) {
	config := ServerConfig{MaxSize: 1000, Accept: []string{"*.txt"}, Reject: []string{"bad.txt"}}
	if got := checkFilter("bad.txt", 1, config); got.reason != filterExtension || got.pattern != "bad.txt" {
		t.Fatalf("reject did not take precedence: %#v", got)
	}
	if got := checkFilter("good.txt", 1001, config); got.reason != filterSize {
		t.Fatalf("oversize accepted: %#v", got)
	}
	if got := checkFilter("good.csv", 1, config); got.reason != filterExtension {
		t.Fatalf("accept list bypassed: %#v", got)
	}
	if got := checkFilter("good.txt", 1, config); got.reason != filterOK {
		t.Fatalf("valid file rejected: %#v", got)
	}
}

func TestConcurrentSaveUsesExclusiveCollisionNames(t *testing.T) {
	dir := t.TempDir()
	const count = 16
	paths := make(chan string, count)
	errors := make(chan error, count)
	var group sync.WaitGroup
	for index := 0; index < count; index++ {
		group.Add(1)
		go func(index int) {
			defer group.Done()
			result, err := save(dir, "same.txt", strings.NewReader("payload"))
			if err != nil {
				errors <- err
				return
			}
			paths <- result.path
		}(index)
	}
	group.Wait()
	close(errors)
	for err := range errors {
		t.Fatal(err)
	}
	close(paths)
	seen := map[string]bool{}
	for path := range paths {
		if seen[path] {
			t.Fatalf("duplicate save path %s", path)
		}
		seen[path] = true
		data, err := os.ReadFile(path)
		if err != nil || string(data) != "payload" {
			t.Fatalf("saved payload at %s = %q, %v", path, data, err)
		}
	}
	if len(seen) != count {
		t.Fatalf("saved %d files, want %d", len(seen), count)
	}
}

func TestSendAndServerRoundTrip(t *testing.T) {
	var key secretbox.Key
	for index := range key {
		key[index] = byte(index)
	}
	dir := t.TempDir()
	logs := new(bytes.Buffer)
	config := DefaultServerConfig()
	config.Dir, config.Logger = dir, logs
	server, err := NewServer(0, config, &key)
	if err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan error, 1)
	go func() { done <- server.Serve(ctx) }()

	address := net.JoinHostPort("127.0.0.1", stringPort(server.Port()))
	if err := Send(context.Background(), address, TextPayload("hello"), &key, time.Second); err != nil {
		t.Fatal(err)
	}
	cancel()
	select {
	case err := <-done:
		if err != nil {
			t.Fatal(err)
		}
	case <-time.After(2 * time.Second):
		t.Fatal("server did not stop")
	}
	data, err := os.ReadFile(filepath.Join(dir, "text.txt"))
	if err != nil || string(data) != "hello" {
		t.Fatalf("received data = %q, %v", data, err)
	}
	if !strings.Contains(logs.String(), "Received: text.txt (5 bytes)") {
		t.Fatalf("missing receipt log: %s", logs)
	}
}

func TestServerRejectionClosesWithoutAck(t *testing.T) {
	var key secretbox.Key
	config := DefaultServerConfig()
	config.MaxSize = 1
	server, err := NewServer(0, config, &key)
	if err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	go server.Serve(ctx)
	connection, err := net.Dial("tcp", net.JoinHostPort("127.0.0.1", stringPort(server.Port())))
	if err != nil {
		t.Fatal(err)
	}
	defer connection.Close()
	var header bytes.Buffer
	binary.Write(&header, binary.BigEndian, uint16(len("x.txt")))
	header.WriteString("x.txt")
	binary.Write(&header, binary.BigEndian, uint64(2))
	if _, err := connection.Write(header.Bytes()); err != nil {
		t.Fatal(err)
	}
	connection.SetReadDeadline(time.Now().Add(time.Second))
	var ack [1]byte
	if _, err := io.ReadFull(connection, ack[:]); err == nil {
		t.Fatalf("rejection sent ack byte %x", ack)
	}
}

func TestStdoutDelivery(t *testing.T) {
	var key secretbox.Key
	var output bytes.Buffer
	config := DefaultServerConfig()
	config.ToStdout, config.Stdout = true, &output
	server, err := NewServer(0, config, &key)
	if err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan error, 1)
	go func() { done <- server.Serve(ctx) }()
	address := net.JoinHostPort("127.0.0.1", stringPort(server.Port()))
	for _, text := range []string{"one", "two"} {
		if err := Send(context.Background(), address, TextPayload(text), &key, time.Second); err != nil {
			t.Fatal(err)
		}
	}
	cancel()
	<-done
	if output.String() != "onetwo" {
		t.Fatalf("stdout = %q", output.String())
	}
}

func TestCollisionSuffixOrder(t *testing.T) {
	dir := t.TempDir()
	var paths []string
	for range 3 {
		result, err := save(dir, "archive.tar.gz", strings.NewReader("x"))
		if err != nil {
			t.Fatal(err)
		}
		paths = append(paths, filepath.Base(result.path))
	}
	sort.Strings(paths)
	want := []string{"archive.tar.gz", "archive.tar_1.gz", "archive.tar_2.gz"}
	for index := range want {
		if paths[index] != want[index] {
			t.Fatalf("paths = %v", paths)
		}
	}
}

func TestNegativeTimeoutsAreRejected(t *testing.T) {
	var key secretbox.Key
	config := DefaultServerConfig()
	config.ReadTimeout = -time.Second
	if _, err := NewServer(0, config, &key); err == nil {
		t.Fatal("negative server read timeout accepted")
	}
	if err := Send(context.Background(), "localhost:1", TextPayload("x"), &key, -time.Second); err == nil {
		t.Fatal("negative client timeout accepted")
	}
}

func stringPort(port uint16) string {
	var buffer [5]byte
	return string(strconvAppendUint(buffer[:0], uint64(port)))
}

func strconvAppendUint(buffer []byte, value uint64) []byte {
	if value >= 10 {
		buffer = strconvAppendUint(buffer, value/10)
	}
	return append(buffer, byte('0'+value%10))
}
