// Package secretbox owns Cauldron's password KDF and detached-tag
// XChaCha20-Poly1305 representation.
package secretbox

import (
	"crypto/rand"
	"errors"
	"fmt"
	"io"

	"golang.org/x/crypto/argon2"
	"golang.org/x/crypto/chacha20poly1305"
)

const (
	KeySize   = chacha20poly1305.KeySize
	NonceSize = chacha20poly1305.NonceSizeX
	TagSize   = 16

	MittSalt       = "mitt-v1-salt-24!"
	SeanceSalt     = "seance-v1-salt!!"
	OmenSalt       = "omen-v1-salt---!"
	CovenantSalt   = "covenant-v1-salt"
	IdentityV2Salt = "covenant-id-v2!!"
)

const (
	argonTime    = uint32(3)
	argonMemory  = uint32(64 * 1024) // KiB
	argonThreads = uint8(4)
)

// Key is an Argon2id-derived symmetric key.
type Key [KeySize]byte

// Box is Cauldron's detached-tag representation. On the wire it is encoded as
// Nonce, Tag, Ciphertext.
type Box struct {
	Nonce      [NonceSize]byte
	Tag        [TagSize]byte
	Ciphertext []byte
}

// Derive applies the exact KDF used by the canonical Zig implementation.
func Derive(password []byte, salt string) (Key, error) {
	if len(salt) != 16 {
		return Key{}, fmt.Errorf("secretbox: salt length %d, want 16", len(salt))
	}
	derived := argon2.IDKey(password, []byte(salt), argonTime, argonMemory, argonThreads, KeySize)
	var key Key
	copy(key[:], derived)
	Zero(derived)
	return key, nil
}

// Seal encrypts plaintext with a fresh nonce from crypto/rand.Reader.
func Seal(key *Key, plaintext []byte) (Box, error) {
	return SealFrom(rand.Reader, key, plaintext)
}

// SealFrom is Seal with an injectable entropy source for deterministic tests.
func SealFrom(random io.Reader, key *Key, plaintext []byte) (Box, error) {
	var nonce [NonceSize]byte
	if _, err := io.ReadFull(random, nonce[:]); err != nil {
		return Box{}, fmt.Errorf("secretbox: nonce: %w", err)
	}
	return SealWithNonce(key, plaintext, nonce)
}

// SealWithNonce exists for compatibility vectors. Production callers should use
// Seal so a nonce is never reused accidentally.
func SealWithNonce(key *Key, plaintext []byte, nonce [NonceSize]byte) (Box, error) {
	if key == nil {
		return Box{}, errors.New("secretbox: nil key")
	}
	aead, err := chacha20poly1305.NewX(key[:])
	if err != nil {
		return Box{}, fmt.Errorf("secretbox: initialize AEAD: %w", err)
	}
	sealed := aead.Seal(nil, nonce[:], plaintext, nil)
	ctLen := len(sealed) - TagSize
	box := Box{Nonce: nonce, Ciphertext: make([]byte, ctLen)}
	copy(box.Ciphertext, sealed[:ctLen])
	copy(box.Tag[:], sealed[ctLen:])
	Zero(sealed)
	return box, nil
}

// Open authenticates and decrypts a detached-tag box using empty AAD.
func Open(key *Key, box Box) ([]byte, error) {
	if key == nil {
		return nil, errors.New("secretbox: nil key")
	}
	aead, err := chacha20poly1305.NewX(key[:])
	if err != nil {
		return nil, fmt.Errorf("secretbox: initialize AEAD: %w", err)
	}
	attached := make([]byte, len(box.Ciphertext)+TagSize)
	copy(attached, box.Ciphertext)
	copy(attached[len(box.Ciphertext):], box.Tag[:])
	defer Zero(attached)
	plaintext, err := aead.Open(nil, box.Nonce[:], attached, nil)
	if err != nil {
		return nil, fmt.Errorf("secretbox: authenticate: %w", err)
	}
	return plaintext, nil
}

// Zero overwrites an owned byte slice on a best-effort basis.
func Zero(b []byte) {
	for i := range b {
		b[i] = 0
	}
}

// ZeroKey overwrites an owned key on a best-effort basis.
func ZeroKey(key *Key) {
	if key != nil {
		Zero(key[:])
	}
}
