package omen

import (
	"bytes"
	"testing"

	"github.com/no-way-labs/cauldron/internal/sigcrypto"
)

func protocolPeers(t *testing.T) []Peer {
	t.Helper()
	first, err := sigcrypto.GenerateIdentityFrom(bytes.NewReader(bytes.Repeat([]byte{1}, 64)))
	if err != nil {
		t.Fatal(err)
	}
	second, err := sigcrypto.GenerateIdentityFrom(bytes.NewReader(bytes.Repeat([]byte{2}, 64)))
	if err != nil {
		t.Fatal(err)
	}
	return []Peer{{Slot: 0, Nick: "host", PublicKey: first.Public()}, {Slot: 1, Nick: "voter", PublicKey: second.Public()}}
}

func TestProtocolPayloadRoundTrips(t *testing.T) {
	ballot := Ballot{Question: "Question?", Options: []string{"yes", "nø"}}
	ballot.SessionID[0] = 9
	encoded, err := EncodeBallot(ballot)
	if err != nil {
		t.Fatal(err)
	}
	decoded, err := DecodeBallot(encoded)
	if err != nil || decoded.Question != ballot.Question || decoded.SessionID != ballot.SessionID || len(decoded.Options) != 2 || decoded.Options[1] != "nø" {
		t.Fatalf("ballot roundtrip: %#v, %v", decoded, err)
	}

	peers := protocolPeers(t)
	peerBytes, err := EncodePeerList(peers)
	if err != nil {
		t.Fatal(err)
	}
	peerDecoded, err := DecodePeerList(peerBytes)
	if err != nil || !equalPeerLists(peers, peerDecoded) {
		t.Fatalf("peer roundtrip: %#v, %v", peerDecoded, err)
	}

	commitments := []Commitment{{Slot: 0}, {Slot: 1}}
	commitments[0].Commitment[0] = 3
	commitments[1].Signature[63] = 4
	setHash := commitSetHash(commitments)
	commitBytes, err := EncodeCommitSet(commitments, setHash)
	if err != nil {
		t.Fatal(err)
	}
	commitDecoded, hashDecoded, err := DecodeCommitSet(commitBytes)
	if err != nil || hashDecoded != setHash || len(commitDecoded) != 2 || commitDecoded[1] != commitments[1] {
		t.Fatalf("commit roundtrip: %#v, %x, %v", commitDecoded, hashDecoded, err)
	}

	reveals := []Reveal{{Vote: 1}, {Vote: 0}}
	reveals[0].Blinding[2] = 8
	revealBytes, err := EncodeRevealSet(reveals)
	if err != nil {
		t.Fatal(err)
	}
	revealDecoded, err := DecodeRevealSet(revealBytes)
	if err != nil || len(revealDecoded) != 2 || revealDecoded[0] != reveals[0] {
		t.Fatalf("reveal roundtrip: %#v, %v", revealDecoded, err)
	}
}

func TestProtocolRejectsTrailingTruncatedAndNonCanonicalPayloads(t *testing.T) {
	ballot, err := EncodeBallot(Ballot{Question: "?", Options: []string{"a", "b"}})
	if err != nil {
		t.Fatal(err)
	}
	for _, malformed := range [][]byte{ballot[:len(ballot)-1], append(append([]byte(nil), ballot...), 0)} {
		if _, err := DecodeBallot(malformed); err == nil {
			t.Fatalf("accepted malformed ballot %x", malformed)
		}
	}
	peers, err := EncodePeerList(protocolPeers(t))
	if err != nil {
		t.Fatal(err)
	}
	peers[1] = 1 // first slot must be zero
	if _, err := DecodePeerList(peers); err == nil {
		t.Fatal("accepted noncanonical slots")
	}

	commitments := []Commitment{{Slot: 0}, {Slot: 1}}
	payload, err := EncodeCommitSet(commitments, sigcrypto.Hash{})
	if err != nil {
		t.Fatal(err)
	}
	payload[1+97] = 0 // duplicate slot zero
	if _, _, err := DecodeCommitSet(payload); err == nil {
		t.Fatal("accepted duplicate commitment slot")
	}
	if _, err := DecodeRevealSet([]byte{2, 0}); err == nil {
		t.Fatal("accepted truncated reveal set")
	}
}

func FuzzProtocolDecoders(f *testing.F) {
	f.Add([]byte{})
	f.Add([]byte{2, 0, 0})
	f.Fuzz(func(t *testing.T, data []byte) {
		_, _ = DecodeBallot(data)
		_, _ = DecodePeerList(data)
		_, _, _ = DecodeCommitSet(data)
		_, _ = DecodeRevealSet(data)
		_, _, _ = DecodePhase(data)
		_, _ = DecodeCommitment(data, 0)
		_, _ = DecodeReveal(data)
	})
}
