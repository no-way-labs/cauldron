package sigcrypto

import (
	"bytes"
	"testing"
)

func TestIdentityAndSignatures(t *testing.T) {
	first, err := DeriveIdentity([]byte("correct horse battery staple"))
	if err != nil {
		t.Fatal(err)
	}
	defer first.Zero()
	second, err := DeriveIdentity([]byte("correct horse battery staple"))
	if err != nil {
		t.Fatal(err)
	}
	defer second.Zero()
	if first.Public() != second.Public() {
		t.Fatal("deterministic identity changed")
	}
	signature, err := first.Sign([]byte("roster"))
	if err != nil {
		t.Fatal(err)
	}
	if !Verify(first.Public(), []byte("roster"), signature) {
		t.Fatal("valid signature rejected")
	}
	if Verify(first.Public(), []byte("other"), signature) {
		t.Fatal("signature verified for different message")
	}
}

func TestRosterFormatsDifferAndCovenantSorts(t *testing.T) {
	var a, b PublicKey
	a[31] = 1
	b[31] = 2
	omen, err := OmenRosterHash([]OmenPeer{
		{Slot: 0, Nick: "alice", PublicKey: a},
		{Slot: 1, Nick: "bob", PublicKey: b},
	})
	if err != nil {
		t.Fatal(err)
	}
	covenant, sorted, err := CovenantRosterHash([]CovenantMember{
		{Nick: "bob", PublicKey: b},
		{Nick: "alice", PublicKey: a},
	})
	if err != nil {
		t.Fatal(err)
	}
	if bytes.Equal(omen[:], covenant[:]) {
		t.Fatal("different roster formats produced the same hash")
	}
	if sorted[0].Nick != "alice" || sorted[1].Nick != "bob" {
		t.Fatalf("unexpected sorted order: %#v", sorted)
	}
}

func TestCovenantRosterRejectsDuplicateKeys(t *testing.T) {
	var key PublicKey
	key[0] = 1
	_, _, err := CovenantRosterHash([]CovenantMember{
		{Nick: "a", PublicKey: key}, {Nick: "b", PublicKey: key},
	})
	if err == nil {
		t.Fatal("duplicate public keys accepted")
	}
}
