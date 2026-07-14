package covenant

import (
	"bytes"
	"context"
	"errors"
	"net"
	"strconv"
	"strings"
	"testing"
	"time"

	"github.com/no-way-labs/cauldron/internal/secretbox"
	"github.com/no-way-labs/cauldron/internal/sigcrypto"
)

func TestGoCeremonyEndToEnd(t *testing.T) {
	var key secretbox.Key
	for index := range key {
		key[index] = byte(index)
	}
	host := testIdentity(t, 3)
	defer host.Zero()
	joiner := testIdentity(t, 4)
	defer joiner.Zero()
	var logs bytes.Buffer
	fixed := time.Unix(1_700_000_000, 0)
	server, err := NewServer(ServerConfig{
		Nick: "host", GroupName: "test group", Version: "0.2.0", Logger: &logs,
		Now: func() time.Time { return fixed }, Random: bytes.NewReader(bytes.Repeat([]byte{9}, 32)),
	}, &key, &host)
	if err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	serverResult := make(chan struct {
		artifact []byte
		err      error
	}, 1)
	go func() {
		artifact, err := server.Run(ctx)
		serverResult <- struct {
			artifact []byte
			err      error
		}{artifact, err}
	}()
	client, err := Connect(ctx, ClientConfig{
		Address: net.JoinHostPort("127.0.0.1", strconv.Itoa(int(server.Port()))),
		Nick:    "alice", Timeout: time.Second, TimeoutSet: true, Now: func() time.Time { return fixed },
	}, &key, &joiner)
	if err != nil {
		t.Fatal(err)
	}
	clientResult := make(chan struct {
		artifact []byte
		err      error
	}, 1)
	go func() {
		artifact, err := client.Run(ctx)
		clientResult <- struct {
			artifact []byte
			err      error
		}{artifact, err}
	}()
	waitReady(t, server, 1, 1)
	if err := server.Seal(); err != nil {
		t.Fatal(err)
	}

	clientDone := <-clientResult
	if clientDone.err != nil {
		t.Fatal("client:", clientDone.err)
	}
	serverDone := <-serverResult
	if serverDone.err != nil {
		t.Fatal("server:", serverDone.err)
	}
	if !bytes.Equal(clientDone.artifact, serverDone.artifact) {
		t.Fatal("host and client received different artifacts")
	}
	verified, err := VerifyArtifact(serverDone.artifact)
	if err != nil || !verified.Valid || verified.MemberCount != 2 || verified.GroupName != "test group" {
		t.Fatalf("verification = %#v, %v", verified, err)
	}
	if !strings.Contains(logs.String(), "COVENANT SEALED") {
		t.Fatalf("missing completion log: %s", &logs)
	}
}

func TestDuplicateIdentityIsRejectedBeforeSeal(t *testing.T) {
	var key secretbox.Key
	host := testIdentity(t, 5)
	defer host.Zero()
	shared := testIdentity(t, 6)
	defer shared.Zero()
	server, err := NewServer(ServerConfig{
		Nick: "host", GroupName: "g", Version: "0.2.0",
	}, &key, &host)
	if err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	serverDone := make(chan error, 1)
	go func() { _, err := server.Run(ctx); serverDone <- err }()
	address := net.JoinHostPort("127.0.0.1", strconv.Itoa(int(server.Port())))
	first, err := Connect(ctx, ClientConfig{Address: address, Nick: "one", Timeout: time.Second, TimeoutSet: true}, &key, &shared)
	if err != nil {
		t.Fatal(err)
	}
	firstDone := make(chan error, 1)
	go func() { _, err := first.Run(ctx); firstDone <- err }()
	waitReady(t, server, 1, 1)
	second, err := Connect(ctx, ClientConfig{Address: address, Nick: "two", Timeout: time.Second, TimeoutSet: true}, &key, &shared)
	if err != nil {
		t.Fatal(err)
	}
	_, secondErr := second.Run(ctx)
	if secondErr == nil {
		t.Fatal("duplicate identity remained connected")
	}
	waitReady(t, server, 1, 1)
	if err := server.Seal(); err != nil {
		t.Fatal(err)
	}
	if err := <-firstDone; err != nil {
		t.Fatal(err)
	}
	if err := <-serverDone; err != nil {
		t.Fatal(err)
	}
}

func TestWrongRoomKeyIsSilentlyRejected(t *testing.T) {
	var key, wrong secretbox.Key
	wrong[0] = 1
	host := testIdentity(t, 7)
	defer host.Zero()
	joiner := testIdentity(t, 8)
	defer joiner.Zero()
	server, err := NewServer(ServerConfig{Nick: "host", GroupName: "g", Version: "0.2.0"}, &key, &host)
	if err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithTimeout(context.Background(), 3*time.Second)
	defer cancel()
	serverDone := make(chan error, 1)
	go func() { _, err := server.Run(ctx); serverDone <- err }()
	client, err := Connect(ctx, ClientConfig{
		Address: net.JoinHostPort("127.0.0.1", strconv.Itoa(int(server.Port()))),
		Nick:    "alice", Timeout: time.Second, TimeoutSet: true,
	}, &wrong, &joiner)
	// The server closes as soon as it cannot decrypt the JOIN. Depending on the
	// TCP stack and scheduling, that close can reach the client during Connect's
	// second write or during Run's first read. Both are successful rejection.
	if err == nil {
		_, err = client.Run(ctx)
	}
	if err == nil {
		t.Fatal("wrong room key was admitted")
	}
	connected, keyed := server.Ready()
	if connected != 0 || keyed != 0 {
		t.Fatalf("wrong-key member admitted: connected=%d keyed=%d", connected, keyed)
	}
	server.Abort()
	if err := <-serverDone; !errors.Is(err, ErrAborted) {
		t.Fatalf("server error = %v", err)
	}
}

func TestArtifactSizePreflightMatchesWriter(t *testing.T) {
	artifact := signedFixture(t)
	encoded := mustArtifact(t, artifact)
	if got := artifactEncodedSize(artifact); got != len(encoded) {
		t.Fatalf("projected size = %d, actual = %d", got, len(encoded))
	}
}

func TestServerRejectsNegativeTimeouts(t *testing.T) {
	var key secretbox.Key
	host := testIdentity(t, 9)
	defer host.Zero()
	base := ServerConfig{Nick: "host", GroupName: "g", Version: "0.2.0"}
	for name, mutate := range map[string]func(*ServerConfig){
		"handshake": func(config *ServerConfig) { config.HandshakeTimeout = -time.Second },
		"delivery":  func(config *ServerConfig) { config.DeliveryTimeout = -time.Second },
	} {
		t.Run(name, func(t *testing.T) {
			config := base
			mutate(&config)
			if _, err := NewServer(config, &key, &host); err == nil {
				t.Fatal("negative timeout accepted")
			}
		})
	}
}

func FuzzDecodeRoster(f *testing.F) {
	seed := make([]byte, 0, 1+2*(1+1+32))
	seed = append(seed, 2, 1, 'a')
	seed = append(seed, make([]byte, 32)...)
	seed = append(seed, 1, 'b')
	seed = append(seed, bytes.Repeat([]byte{1}, 32)...)
	f.Add(seed)
	f.Add([]byte{})
	f.Fuzz(func(t *testing.T, input []byte) {
		members, err := DecodeRoster(input)
		if err != nil {
			return
		}
		encoded, err := EncodeRoster(members)
		if err != nil {
			t.Fatalf("decoded roster could not be re-encoded: %v", err)
		}
		if !bytes.Equal(encoded, input) {
			t.Fatalf("noncanonical roster accepted: %x != %x", input, encoded)
		}
	})
}

func waitReady(t *testing.T, server *Server, connected, keyed int) {
	t.Helper()
	deadline := time.Now().Add(2 * time.Second)
	for time.Now().Before(deadline) {
		gotConnected, gotKeyed := server.Ready()
		if gotConnected == connected && gotKeyed == keyed {
			return
		}
		time.Sleep(time.Millisecond)
	}
	gotConnected, gotKeyed := server.Ready()
	t.Fatalf("server readiness = %d/%d, want %d/%d", gotConnected, gotKeyed, connected, keyed)
}

func testIdentity(t *testing.T, seed byte) sigcrypto.KeyPair {
	t.Helper()
	identity, err := sigcrypto.GenerateIdentityFrom(bytes.NewReader(bytes.Repeat([]byte{seed}, 64)))
	if err != nil {
		t.Fatal(err)
	}
	return identity
}
