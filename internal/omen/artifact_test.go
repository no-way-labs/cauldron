package omen

import (
	"bytes"
	"encoding/hex"
	"fmt"
	"strings"
	"testing"
	"time"

	"github.com/no-way-labs/cauldron/internal/jsonstrict"
	"github.com/no-way-labs/cauldron/internal/sigcrypto"
)

func TestArtifactRoundTripUsesActualTopLevelSignatureKey(t *testing.T) {
	artifact, host, voter := artifactFixture(t)
	defer host.Zero()
	defer voter.Zero()
	artifact.Question = `Should the text "host_signature" be harmless?`
	encoded, err := BuildArtifact(artifact, &host)
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.HasPrefix(encoded, []byte(`{"omen_version":"0.2.0","session_id":"00010203`)) {
		t.Fatalf("unexpected artifact prefix: %.100s", encoded)
	}
	result, err := VerifyArtifact(encoded)
	if err != nil {
		t.Fatal(err)
	}
	if !result.Valid || result.Question != artifact.Question {
		t.Fatalf("verification = %#v", result)
	}
	if len(result.RevealSlots) != 2 || result.RevealSlots[0] != 1 || result.RevealSlots[1] != 0 {
		t.Fatalf("reveals did not link to roster slots: %v", result.RevealSlots)
	}
}

func TestDuplicateCommitmentSlotExploitIsRejected(t *testing.T) {
	artifact, host, voter := artifactFixture(t)
	defer host.Zero()
	defer voter.Zero()
	encoded, err := BuildArtifact(artifact, &host)
	if err != nil {
		t.Fatal(err)
	}
	firstCommitment := commitmentJSON(artifact.Commitments[0])
	secondCommitment := commitmentJSON(artifact.Commitments[1])
	tampered := bytes.Replace(encoded, []byte(secondCommitment), []byte(firstCommitment), 1)
	firstReveal := revealJSON(artifact.Reveals[0])
	secondReveal := revealJSON(artifact.Reveals[1])
	// Both votes are option zero, so duplicating slot 0's reveal keeps the tally
	// unchanged while replacing slot 1's signed commitment.
	tampered = bytes.Replace(tampered, []byte(firstReveal), []byte(secondReveal), 1)
	tampered = resign(t, tampered, &host)
	if _, err := VerifyArtifact(tampered); err == nil || !strings.Contains(err.Error(), "slot coverage") {
		t.Fatalf("duplicate slot exploit error = %v", err)
	}
}

func TestDuplicateKeysOptionsAndStaleCountsAreRejected(t *testing.T) {
	artifact, host, voter := artifactFixture(t)
	defer host.Zero()
	defer voter.Zero()
	encoded, err := BuildArtifact(artifact, &host)
	if err != nil {
		t.Fatal(err)
	}
	duplicateKey := bytes.Replace(encoded, []byte(`{"omen_version":"0.2.0",`),
		[]byte(`{"omen_version":"0.2.0","omen_version":"9",`), 1)
	if _, err := VerifyArtifact(duplicateKey); err == nil || !strings.Contains(err.Error(), "duplicate") {
		t.Fatalf("duplicate key error = %v", err)
	}
	duplicateOption := cloneArtifact(artifact)
	duplicateOption.Options[1] = duplicateOption.Options[0]
	if _, err := BuildArtifact(duplicateOption, &host); err == nil || !strings.Contains(err.Error(), "duplicate option") {
		t.Fatalf("duplicate option error = %v", err)
	}
	stale := bytes.Replace(encoded, []byte(`"voter_count":2`), []byte(`"voter_count":3`), 1)
	if _, err := VerifyArtifact(stale); err == nil || !strings.Contains(err.Error(), "voter_count") {
		t.Fatalf("stale voter count error = %v", err)
	}
}

func TestHostSignatureMustBeLast(t *testing.T) {
	artifact, host, voter := artifactFixture(t)
	defer host.Zero()
	defer voter.Zero()
	encoded, err := BuildArtifact(artifact, &host)
	if err != nil {
		t.Fatal(err)
	}
	tampered := append(append([]byte(nil), encoded[:len(encoded)-1]...), []byte(`,"unsigned_extension":true}`)...)
	if _, err := VerifyArtifact(tampered); err == nil || !strings.Contains(err.Error(), "final") {
		t.Fatalf("post-signature extension error = %v", err)
	}
}

func TestRosterRenameAndInvalidVoteFail(t *testing.T) {
	artifact, host, voter := artifactFixture(t)
	defer host.Zero()
	defer voter.Zero()
	encoded, err := BuildArtifact(artifact, &host)
	if err != nil {
		t.Fatal(err)
	}
	renamed := bytes.Replace(encoded, []byte(`"nick":"host"`), []byte(`"nick":"evil"`), 1)
	result, err := VerifyArtifact(renamed)
	if err != nil {
		t.Fatal(err)
	}
	if result.Valid || result.RosterHashValid {
		t.Fatalf("renamed roster verified: %#v", result)
	}
	invalidVote := bytes.Replace(encoded, []byte(`"vote":0`), []byte(`"vote":9`), 1)
	if _, err := VerifyArtifact(invalidVote); err == nil || !strings.Contains(err.Error(), "vote index") {
		t.Fatalf("invalid vote error = %v", err)
	}
}

func TestV1HostCanRelabelOptionsWhenItResigns(t *testing.T) {
	artifact, host, voter := artifactFixture(t)
	defer host.Zero()
	defer voter.Zero()
	relabelled := cloneArtifact(artifact)
	relabelled.Options = []string{"approve", "reject"}
	relabelled.Winner = "approve"
	encoded, err := BuildArtifact(relabelled, &host)
	if err != nil {
		t.Fatal(err)
	}
	result, err := VerifyArtifact(encoded)
	if err != nil || !result.Valid {
		t.Fatalf("relabelled v1 artifact should remain internally valid: %#v, %v", result, err)
	}
}

func TestCommitSetRequiresExactSlotCoverage(t *testing.T) {
	artifact, host, voter := artifactFixture(t)
	defer host.Zero()
	defer voter.Zero()
	converted := make([]sigcrypto.OmenCommitment, len(artifact.Commitments))
	for index, commitment := range artifact.Commitments {
		converted[index] = sigcrypto.OmenCommitment{Slot: commitment.Slot, Commitment: commitment.Commitment, Signature: commitment.Signature}
	}
	setHash := sigcrypto.OmenCommitSetHash(converted)
	if err := VerifyCommitSet(artifact.Commitments, setHash, artifact.Roster, artifact.RosterHash, nil, nil); err != nil {
		t.Fatal(err)
	}
	bad := append([]Commitment(nil), artifact.Commitments...)
	bad[1] = bad[0]
	if err := VerifyCommitSet(bad, setHash, artifact.Roster, artifact.RosterHash, nil, nil); err == nil {
		t.Fatal("duplicate slot commitment set accepted")
	}
}

func TestMaximumArtifactSizeCoversPreEpochTimestampEncoding(t *testing.T) {
	artifact, host, voter := artifactFixture(t)
	defer host.Zero()
	defer voter.Zero()
	now := time.Unix(-1, 0)
	artifact.Timestamp = uint64(now.Unix())
	encoded, err := BuildArtifact(artifact, &host)
	if err != nil {
		t.Fatal(err)
	}
	ballot := Ballot{SessionID: artifact.SessionID, Question: artifact.Question, Options: artifact.Options}
	if estimate := maximumArtifactSize(artifact.Version, ballot, artifact.Roster, now); estimate < len(encoded) {
		t.Fatalf("maximum artifact estimate = %d, encoded size = %d", estimate, len(encoded))
	}
}

func FuzzVerifyArtifact(f *testing.F) {
	f.Add([]byte(`{"omen_version":"0.1.0"}`))
	f.Add([]byte(`{}`))
	f.Fuzz(func(t *testing.T, data []byte) { _, _ = VerifyArtifact(data) })
}

func artifactFixture(t *testing.T) (Artifact, sigcrypto.KeyPair, sigcrypto.KeyPair) {
	t.Helper()
	host := omenIdentity(t, 11)
	voter := omenIdentity(t, 12)
	roster := []Peer{
		{Slot: 0, Nick: "host", PublicKey: host.Public()},
		{Slot: 1, Nick: "voter", PublicKey: voter.Public()},
	}
	hash, err := rosterHash(roster)
	if err != nil {
		t.Fatal(err)
	}
	var hostBlind, voterBlind [32]byte
	for index := range hostBlind {
		hostBlind[index] = byte(index + 1)
		voterBlind[index] = byte(100 + index)
	}
	hostCommitment := sigcrypto.MakeCommitment(0, hostBlind)
	voterCommitment := sigcrypto.MakeCommitment(0, voterBlind)
	hostSignature, err := sigcrypto.SignOmenCommitment(&host, hash, hostCommitment)
	if err != nil {
		t.Fatal(err)
	}
	voterSignature, err := sigcrypto.SignOmenCommitment(&voter, hash, voterCommitment)
	if err != nil {
		t.Fatal(err)
	}
	var session sigcrypto.Hash
	for index := range session {
		session[index] = byte(index)
	}
	return Artifact{
		Version: "0.2.0", SessionID: session, Timestamp: 1234,
		Question: "Ship it?", Options: []string{"yes", "no"}, VoterCount: 2,
		RosterHash: hash, Roster: roster,
		Commitments: []Commitment{
			{Slot: 0, Commitment: hostCommitment, Signature: hostSignature},
			{Slot: 1, Commitment: voterCommitment, Signature: voterSignature},
		},
		Reveals:       []Reveal{{Vote: 0, Blinding: voterBlind}, {Vote: 0, Blinding: hostBlind}},
		Counts:        []uint32{2, 0},
		Winner:        "yes",
		HostPublicKey: host.Public(),
	}, host, voter
}

func omenIdentity(t *testing.T, seed byte) sigcrypto.KeyPair {
	t.Helper()
	identity, err := sigcrypto.GenerateIdentityFrom(bytes.NewReader(bytes.Repeat([]byte{seed}, 64)))
	if err != nil {
		t.Fatal(err)
	}
	return identity
}

func cloneArtifact(input Artifact) Artifact {
	result := input
	result.Options = append([]string(nil), input.Options...)
	result.Roster = append([]Peer(nil), input.Roster...)
	result.Commitments = append([]Commitment(nil), input.Commitments...)
	result.Reveals = append([]Reveal(nil), input.Reveals...)
	result.Counts = append([]uint32(nil), input.Counts...)
	return result
}

func commitmentJSON(value Commitment) string {
	return fmt.Sprintf(`{"slot":%d,"commitment":"%x","signature":"%x"}`, value.Slot, value.Commitment, value.Signature)
}

func revealJSON(value Reveal) string {
	return fmt.Sprintf(`{"vote":%d,"blinding":"%x"}`, value.Vote, value.Blinding)
}

func resign(t *testing.T, data []byte, host *sigcrypto.KeyPair) []byte {
	t.Helper()
	members, err := jsonstrict.TopLevelMembers(data)
	if err != nil {
		t.Fatal(err)
	}
	offset := members[len(members)-1].KeyOffset
	hash := sigcrypto.Blake256(data[:offset])
	signature, err := host.Sign(hash[:])
	if err != nil {
		t.Fatal(err)
	}
	result := append([]byte(nil), data[:offset]...)
	result = append(result, []byte(`"host_signature":"`)...)
	encoded := make([]byte, hex.EncodedLen(len(signature)))
	hex.Encode(encoded, signature[:])
	result = append(result, encoded...)
	result = append(result, '"', '}')
	return result
}
