package secretbox

import (
	"bytes"
	"testing"
)

func TestSaltsAreExactLength(t *testing.T) {
	for name, salt := range map[string]string{
		"mitt": MittSalt, "seance": SeanceSalt, "omen": OmenSalt,
		"covenant": CovenantSalt, "identity": IdentityV2Salt,
	} {
		if len(salt) != 16 {
			t.Fatalf("%s salt has length %d", name, len(salt))
		}
	}
}

func TestDetachedRoundTrip(t *testing.T) {
	key, err := Derive([]byte("compat-password"), MittSalt)
	if err != nil {
		t.Fatal(err)
	}
	defer ZeroKey(&key)

	var nonce [NonceSize]byte
	for i := range nonce {
		nonce[i] = byte(i)
	}
	box, err := SealWithNonce(&key, []byte("cauldron compatibility"), nonce)
	if err != nil {
		t.Fatal(err)
	}
	if len(box.Tag) != TagSize || len(box.Ciphertext) != len("cauldron compatibility") {
		t.Fatalf("unexpected detached lengths: tag=%d ciphertext=%d", len(box.Tag), len(box.Ciphertext))
	}
	got, err := Open(&key, box)
	if err != nil {
		t.Fatal(err)
	}
	defer Zero(got)
	if !bytes.Equal(got, []byte("cauldron compatibility")) {
		t.Fatalf("plaintext mismatch: %q", got)
	}

	box.Tag[0] ^= 1
	if _, err := Open(&key, box); err == nil {
		t.Fatal("tampered tag authenticated")
	}
}
