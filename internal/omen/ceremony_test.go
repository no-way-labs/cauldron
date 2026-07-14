package omen

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"testing"
	"time"

	"github.com/no-way-labs/cauldron/internal/secretbox"
	"github.com/no-way-labs/cauldron/internal/sigcrypto"
)

func TestCeremonyEndToEndAndFinalStateBinding(t *testing.T) {
	host, err := sigcrypto.GenerateIdentity()
	if err != nil {
		t.Fatal(err)
	}
	defer host.Zero()
	voter, err := sigcrypto.GenerateIdentity()
	if err != nil {
		t.Fatal(err)
	}
	defer voter.Zero()
	var key secretbox.Key
	copy(key[:], bytes.Repeat([]byte{7}, len(key)))
	server, err := NewServer(ServerConfig{
		Nick: "host", Question: "Tea?", Options: []string{"yes", "no"}, Version: "0.2.0",
	}, &key, &host)
	if err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	serverResult := make(chan struct {
		artifact []byte
		err      error
	}, 1)
	go func() {
		artifact, runErr := server.Run(ctx)
		serverResult <- struct {
			artifact []byte
			err      error
		}{artifact, runErr}
	}()
	client, err := Connect(ctx, ClientConfig{
		Address: fmt.Sprintf("127.0.0.1:%d", server.Port()), Nick: "voter",
		Vote: func(Ballot) (byte, error) { return 1, nil },
	}, &key, &voter)
	if err != nil {
		t.Fatal(err)
	}
	clientResult := make(chan struct {
		artifact []byte
		err      error
	}, 1)
	go func() {
		artifact, runErr := client.Run(ctx)
		clientResult <- struct {
			artifact []byte
			err      error
		}{artifact, runErr}
	}()
	waitReady(t, server, 1, 1)
	if err := server.Start(0); err != nil {
		t.Fatal(err)
	}
	clientDone := <-clientResult
	if clientDone.err != nil {
		t.Fatal(clientDone.err)
	}
	serverDone := <-serverResult
	if serverDone.err != nil {
		t.Fatal(serverDone.err)
	}
	if !bytes.Equal(clientDone.artifact, serverDone.artifact) {
		t.Fatal("host and voter artifacts differ")
	}
	verified, err := VerifyArtifact(serverDone.artifact)
	if err != nil || !verified.Valid || len(verified.RevealSlots) != 2 {
		t.Fatalf("final verification: %#v, %v", verified, err)
	}
	if verified.Counts[0] != 1 || verified.Counts[1] != 1 {
		t.Fatalf("unexpected tally: %v", verified.Counts)
	}
}

func TestRestrictedRosterRejectsDuplicateAndUnlistedIdentities(t *testing.T) {
	host, _ := sigcrypto.GenerateIdentity()
	allowed, _ := sigcrypto.GenerateIdentity()
	unlisted, _ := sigcrypto.GenerateIdentity()
	defer host.Zero()
	defer allowed.Zero()
	defer unlisted.Zero()
	var key secretbox.Key
	server, err := NewServer(ServerConfig{
		Nick: "host", Question: "?", Options: []string{"a", "b"}, Version: "test",
		AllowedPublicKeys: []sigcrypto.PublicKey{host.Public(), allowed.Public()},
	}, &key, &host)
	if err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	runDone := make(chan error, 1)
	go func() { _, runErr := server.Run(ctx); runDone <- runErr }()
	bad, err := Connect(ctx, ClientConfig{
		Address: fmt.Sprintf("127.0.0.1:%d", server.Port()), Nick: "bad",
		Vote: func(Ballot) (byte, error) { return 0, nil },
	}, &key, &unlisted)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := bad.Run(ctx); err == nil {
		t.Fatal("unlisted identity was admitted")
	}
	server.Abort()
	if err := <-runDone; !errors.Is(err, ErrAborted) {
		t.Fatalf("server abort result: %v", err)
	}

	if _, err := NewServer(ServerConfig{
		Nick: "host", Question: "?", Options: []string{"a", "b"}, Version: "test",
		AllowedPublicKeys: []sigcrypto.PublicKey{host.Public(), host.Public()},
	}, &key, &host); err == nil {
		t.Fatal("duplicate restricted roster was accepted")
	}
	if _, err := NewServer(ServerConfig{
		Nick: "host", Question: "?", Options: []string{"a", "b"}, Version: "test",
		AllowedPublicKeys: []sigcrypto.PublicKey{host.Public()},
	}, &key, &host); err == nil {
		t.Fatal("undersized restricted roster was accepted")
	}
}

func TestStartRequiresEveryConnectedVoterKey(t *testing.T) {
	host, _ := sigcrypto.GenerateIdentity()
	defer host.Zero()
	var key secretbox.Key
	server, err := NewServer(ServerConfig{Nick: "host", Question: "?", Options: []string{"a", "b"}, Version: "test"}, &key, &host)
	if err != nil {
		t.Fatal(err)
	}
	defer server.listener.Close()
	server.mu.Lock()
	server.voters = append(server.voters, &remoteVoter{nick: "pending"})
	server.mu.Unlock()
	if !errors.Is(server.Start(0), ErrNotReady) {
		t.Fatal("started with an unkeyed voter")
	}
}

func waitReady(t *testing.T, server *Server, connected, keyed int) {
	t.Helper()
	deadline := time.Now().Add(3 * time.Second)
	for time.Now().Before(deadline) {
		gotConnected, gotKeyed := server.Ready()
		if gotConnected == connected && gotKeyed == keyed {
			return
		}
		time.Sleep(5 * time.Millisecond)
	}
	gotConnected, gotKeyed := server.Ready()
	t.Fatalf("server readiness = %d/%d, want %d/%d", gotConnected, gotKeyed, connected, keyed)
}
