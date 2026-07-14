// Package sigcrypto implements the exact Ed25519 and BLAKE2b surfaces shared by
// omen and covenant. The two roster hash formats deliberately have separate
// functions because their byte order differs.
package sigcrypto

import (
	"bytes"
	"crypto/ed25519"
	"crypto/rand"
	"errors"
	"fmt"
	"io"
	"sort"

	"github.com/no-way-labs/cauldron/internal/secretbox"
	"golang.org/x/crypto/blake2b"
)

const (
	PublicKeySize  = ed25519.PublicKeySize
	PrivateKeySize = ed25519.PrivateKeySize
	SignatureSize  = ed25519.SignatureSize
	HashSize       = blake2b.Size256
)

type PublicKey [PublicKeySize]byte
type Signature [SignatureSize]byte
type Hash [HashSize]byte

// KeyPair owns an Ed25519 private key. Call Zero when it is no longer needed.
type KeyPair struct {
	public  PublicKey
	private ed25519.PrivateKey
}

func DeriveIdentity(passphrase []byte) (KeyPair, error) {
	seed, err := secretbox.Derive(passphrase, secretbox.IdentityV2Salt)
	if err != nil {
		return KeyPair{}, err
	}
	defer secretbox.ZeroKey(&seed)
	private := ed25519.NewKeyFromSeed(seed[:])
	return keyPairFromPrivate(private), nil
}

func GenerateIdentity() (KeyPair, error) {
	return GenerateIdentityFrom(rand.Reader)
}

func GenerateIdentityFrom(random io.Reader) (KeyPair, error) {
	_, private, err := ed25519.GenerateKey(random)
	if err != nil {
		return KeyPair{}, fmt.Errorf("sigcrypto: generate identity: %w", err)
	}
	return keyPairFromPrivate(private), nil
}

func keyPairFromPrivate(private ed25519.PrivateKey) KeyPair {
	var public PublicKey
	copy(public[:], private[32:])
	return KeyPair{public: public, private: private}
}

func (k *KeyPair) Public() PublicKey {
	if k == nil {
		return PublicKey{}
	}
	return k.public
}

func (k *KeyPair) Sign(message []byte) (Signature, error) {
	if k == nil || len(k.private) != PrivateKeySize {
		return Signature{}, errors.New("sigcrypto: unavailable private key")
	}
	var signature Signature
	copy(signature[:], ed25519.Sign(k.private, message))
	return signature, nil
}

func (k *KeyPair) Zero() {
	if k == nil {
		return
	}
	secretbox.Zero(k.private)
	k.private = nil
	k.public = PublicKey{}
}

func Verify(public PublicKey, message []byte, signature Signature) bool {
	return ed25519.Verify(ed25519.PublicKey(public[:]), message, signature[:])
}

func Blake256(parts ...[]byte) Hash {
	h, _ := blake2b.New256(nil)
	for _, part := range parts {
		_, _ = h.Write(part)
	}
	var result Hash
	copy(result[:], h.Sum(nil))
	return result
}

type OmenPeer struct {
	Slot      byte
	Nick      string
	PublicKey PublicKey
}

type OmenCommitment struct {
	Slot       byte
	Commitment Hash
	Signature  Signature
}

func MakeCommitment(vote byte, blinding [32]byte) Hash {
	return Blake256([]byte{vote}, blinding[:])
}

// OmenRosterHash hashes peers in supplied order; it does not sort or validate
// canonical slot coverage.
func OmenRosterHash(peers []OmenPeer) (Hash, error) {
	h, _ := blake2b.New256(nil)
	for _, peer := range peers {
		if len(peer.Nick) > 255 {
			return Hash{}, fmt.Errorf("sigcrypto: omen nick length %d exceeds u8", len(peer.Nick))
		}
		_, _ = h.Write([]byte{peer.Slot, byte(len(peer.Nick))})
		_, _ = h.Write([]byte(peer.Nick))
		_, _ = h.Write(peer.PublicKey[:])
	}
	var result Hash
	copy(result[:], h.Sum(nil))
	return result, nil
}

func OmenCommitSetHash(commitments []OmenCommitment) Hash {
	h, _ := blake2b.New256(nil)
	for _, commitment := range commitments {
		_, _ = h.Write([]byte{commitment.Slot})
		_, _ = h.Write(commitment.Commitment[:])
	}
	var result Hash
	copy(result[:], h.Sum(nil))
	return result
}

func SignOmenCommitment(key *KeyPair, rosterHash, commitment Hash) (Signature, error) {
	message := make([]byte, 0, 2*HashSize)
	message = append(message, rosterHash[:]...)
	message = append(message, commitment[:]...)
	defer secretbox.Zero(message)
	return key.Sign(message)
}

func VerifyOmenCommitment(public PublicKey, rosterHash, commitment Hash, signature Signature) bool {
	var message [2 * HashSize]byte
	copy(message[:HashSize], rosterHash[:])
	copy(message[HashSize:], commitment[:])
	return Verify(public, message[:], signature)
}

type CovenantMember struct {
	Nick      string
	PublicKey PublicKey
}

// CovenantRosterHash sorts a copy by public key before hashing. Equal public
// keys are rejected because their order and identity would be ambiguous.
func CovenantRosterHash(members []CovenantMember) (Hash, []CovenantMember, error) {
	sorted := append([]CovenantMember(nil), members...)
	sort.Slice(sorted, func(i, j int) bool {
		return bytes.Compare(sorted[i].PublicKey[:], sorted[j].PublicKey[:]) < 0
	})
	h, _ := blake2b.New256(nil)
	for i, member := range sorted {
		if len(member.Nick) > 255 {
			return Hash{}, nil, fmt.Errorf("sigcrypto: covenant nick length %d exceeds u8", len(member.Nick))
		}
		if i > 0 && bytes.Equal(sorted[i-1].PublicKey[:], member.PublicKey[:]) {
			return Hash{}, nil, errors.New("sigcrypto: duplicate covenant public key")
		}
		_, _ = h.Write(member.PublicKey[:])
		_, _ = h.Write([]byte{byte(len(member.Nick))})
		_, _ = h.Write([]byte(member.Nick))
	}
	var result Hash
	copy(result[:], h.Sum(nil))
	return result, sorted, nil
}

func SignCovenantRoster(key *KeyPair, rosterHash Hash) (Signature, error) {
	return key.Sign(rosterHash[:])
}

func VerifyCovenantRoster(public PublicKey, rosterHash Hash, signature Signature) bool {
	return Verify(public, rosterHash[:], signature)
}
