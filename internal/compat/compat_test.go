package compat_test

import (
	"bufio"
	"encoding/hex"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/no-way-labs/cauldron/internal/secretbox"
	"github.com/no-way-labs/cauldron/internal/sigcrypto"
)

func TestCanonicalZigVectors(t *testing.T) {
	vectors := loadVectors(t)
	password := []byte("compat-password")
	for name, salt := range map[string]string{
		"mitt_key": secretbox.MittSalt, "seance_key": secretbox.SeanceSalt,
		"omen_key": secretbox.OmenSalt, "covenant_key": secretbox.CovenantSalt,
	} {
		key, err := secretbox.Derive(password, salt)
		if err != nil {
			t.Fatal(err)
		}
		expectHex(t, vectors, name, key[:])
		secretbox.ZeroKey(&key)
	}

	alice, err := sigcrypto.DeriveIdentity([]byte("alice identity"))
	if err != nil {
		t.Fatal(err)
	}
	defer alice.Zero()
	bob, err := sigcrypto.DeriveIdentity([]byte("bob identity"))
	if err != nil {
		t.Fatal(err)
	}
	defer bob.Zero()
	alicePublic, bobPublic := alice.Public(), bob.Public()
	expectHex(t, vectors, "alice_public_key", alicePublic[:])
	expectHex(t, vectors, "bob_public_key", bobPublic[:])

	mittKey, err := secretbox.Derive(password, secretbox.MittSalt)
	if err != nil {
		t.Fatal(err)
	}
	defer secretbox.ZeroKey(&mittKey)
	var nonce [secretbox.NonceSize]byte
	copy(nonce[:], mustDecode(t, vectors["nonce"]))
	box, err := secretbox.SealWithNonce(&mittKey, []byte("cauldron compatibility"), nonce)
	if err != nil {
		t.Fatal(err)
	}
	expectHex(t, vectors, "ciphertext", box.Ciphertext)
	expectHex(t, vectors, "tag", box.Tag[:])

	var blindA, blindB [32]byte
	for i := range blindA {
		blindA[i] = byte(i)
		blindB[i] = byte(0xa0 + i)
	}
	commitmentA := sigcrypto.MakeCommitment(1, blindA)
	commitmentB := sigcrypto.MakeCommitment(0, blindB)
	expectHex(t, vectors, "commitment_a", commitmentA[:])
	expectHex(t, vectors, "commitment_b", commitmentB[:])

	rosterHash, err := sigcrypto.OmenRosterHash([]sigcrypto.OmenPeer{
		{Slot: 0, Nick: "alice", PublicKey: alicePublic},
		{Slot: 1, Nick: "bob", PublicKey: bobPublic},
	})
	if err != nil {
		t.Fatal(err)
	}
	expectHex(t, vectors, "omen_roster_hash", rosterHash[:])
	signatureA, err := sigcrypto.SignOmenCommitment(&alice, rosterHash, commitmentA)
	if err != nil {
		t.Fatal(err)
	}
	signatureB, err := sigcrypto.SignOmenCommitment(&bob, rosterHash, commitmentB)
	if err != nil {
		t.Fatal(err)
	}
	expectHex(t, vectors, "commitment_signature_a", signatureA[:])
	expectHex(t, vectors, "commitment_signature_b", signatureB[:])
	commitSetHash := sigcrypto.OmenCommitSetHash([]sigcrypto.OmenCommitment{
		{Slot: 0, Commitment: commitmentA, Signature: signatureA},
		{Slot: 1, Commitment: commitmentB, Signature: signatureB},
	})
	expectHex(t, vectors, "commit_set_hash", commitSetHash[:])

	covenantHash, _, err := sigcrypto.CovenantRosterHash([]sigcrypto.CovenantMember{
		{Nick: "alice", PublicKey: alicePublic}, {Nick: "bob", PublicKey: bobPublic},
	})
	if err != nil {
		t.Fatal(err)
	}
	expectHex(t, vectors, "covenant_roster_hash", covenantHash[:])
	covenantSignature, err := sigcrypto.SignCovenantRoster(&alice, covenantHash)
	if err != nil {
		t.Fatal(err)
	}
	expectHex(t, vectors, "covenant_signature_a", covenantSignature[:])
}

func loadVectors(t *testing.T) map[string]string {
	t.Helper()
	path := filepath.Join("..", "..", "testdata", "compat", "vectors.txt")
	file, err := os.Open(path)
	if err != nil {
		t.Fatal(err)
	}
	defer file.Close()
	result := make(map[string]string)
	scanner := bufio.NewScanner(file)
	for scanner.Scan() {
		name, value, ok := strings.Cut(scanner.Text(), "=")
		if !ok || name == "" || value == "" {
			t.Fatalf("malformed vector line %q", scanner.Text())
		}
		if _, duplicate := result[name]; duplicate {
			t.Fatalf("duplicate vector %q", name)
		}
		result[name] = value
	}
	if err := scanner.Err(); err != nil {
		t.Fatal(err)
	}
	return result
}

func expectHex(t *testing.T, vectors map[string]string, name string, got []byte) {
	t.Helper()
	want, ok := vectors[name]
	if !ok {
		t.Fatalf("missing vector %q", name)
	}
	if encoded := hex.EncodeToString(got); encoded != want {
		t.Fatalf("%s = %s, want %s", name, encoded, want)
	}
}

func mustDecode(t *testing.T, value string) []byte {
	t.Helper()
	decoded, err := hex.DecodeString(value)
	if err != nil {
		t.Fatal(err)
	}
	return decoded
}
