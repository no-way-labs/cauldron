package covenant

import (
	"bytes"
	"encoding/json"
	"strings"
	"testing"

	"github.com/no-way-labs/cauldron/internal/sigcrypto"
)

func TestArtifactRoundTripAndExactWriter(t *testing.T) {
	artifact := signedFixture(t)
	artifact.GroupName = "friends \"north\"\n雪"
	encoded, err := BuildArtifact(artifact)
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.HasPrefix(encoded, []byte(`{"covenant_version":"0.2.0","group_name":"friends \"north\"\n雪","created_at":1234,`)) {
		t.Fatalf("unexpected artifact prefix: %s", encoded)
	}
	if bytes.Contains(encoded, []byte("\n")) {
		t.Fatal("writer inserted insignificant whitespace")
	}
	result, err := VerifyArtifact(encoded)
	if err != nil {
		t.Fatal(err)
	}
	if !result.Valid || result.MemberCount != 2 || result.GroupName != artifact.GroupName {
		t.Fatalf("verify result = %#v", result)
	}
}

func TestVerifierRejectsRenamedMember(t *testing.T) {
	encoded := mustArtifact(t, signedFixture(t))
	tampered := bytes.Replace(encoded, []byte(`"nick":"alice"`), []byte(`"nick":"mallory"`), 1)
	if _, err := VerifyArtifact(tampered); err == nil || !strings.Contains(err.Error(), "roster_hash") {
		t.Fatalf("renamed member error = %v", err)
	}
}

func TestVerifierRejectsDuplicateJSONKeys(t *testing.T) {
	encoded := mustArtifact(t, signedFixture(t))
	tampered := bytes.Replace(encoded, []byte(`{"covenant_version":"0.2.0",`),
		[]byte(`{"covenant_version":"0.2.0","covenant_version":"9.9.9",`), 1)
	if _, err := VerifyArtifact(tampered); err == nil || !strings.Contains(err.Error(), "duplicate") {
		t.Fatalf("duplicate key error = %v", err)
	}
}

func TestVerifierRejectsStaleCountAndTrailingValue(t *testing.T) {
	encoded := mustArtifact(t, signedFixture(t))
	stale := bytes.Replace(encoded, []byte(`"member_count":2`), []byte(`"member_count":3`), 1)
	if _, err := VerifyArtifact(stale); err == nil || !strings.Contains(err.Error(), "member_count") {
		t.Fatalf("stale count error = %v", err)
	}
	if _, err := VerifyArtifact(append(encoded, []byte(` {}`)...)); err == nil {
		t.Fatal("trailing JSON accepted")
	}
}

func TestVerifierRejectsDuplicatePublicKeys(t *testing.T) {
	artifact := signedFixture(t)
	encoded := mustArtifact(t, artifact)
	var object map[string]any
	if err := json.Unmarshal(encoded, &object); err != nil {
		t.Fatal(err)
	}
	members := object["members"].([]any)
	first := members[0].(map[string]any)
	second := members[1].(map[string]any)
	second["pubkey"] = first["pubkey"]
	second["signature"] = first["signature"]
	tampered, _ := json.Marshal(object)
	if _, err := VerifyArtifact(tampered); err == nil || !strings.Contains(err.Error(), "duplicate") {
		t.Fatalf("duplicate public key error = %v", err)
	}
}

func TestVerifierAllowsUnknownExtensions(t *testing.T) {
	encoded := mustArtifact(t, signedFixture(t))
	extended := bytes.Replace(encoded, []byte(`,"member_count":2}`), []byte(`,"member_count":2,"extension":{"x":1}}`), 1)
	result, err := VerifyArtifact(extended)
	if err != nil || !result.Valid {
		t.Fatalf("extension rejected: result=%#v err=%v", result, err)
	}
}

func TestRosterCodecStrictRoundTrip(t *testing.T) {
	artifact := signedFixture(t)
	members := make([]Member, len(artifact.Members))
	for index, member := range artifact.Members {
		members[index] = Member{Nick: member.Nick, PublicKey: member.PublicKey}
	}
	encoded, err := EncodeRoster(members)
	if err != nil {
		t.Fatal(err)
	}
	decoded, err := DecodeRoster(encoded)
	if err != nil {
		t.Fatal(err)
	}
	if len(decoded) != len(members) || decoded[0] != members[0] || decoded[1] != members[1] {
		t.Fatalf("decoded roster = %#v", decoded)
	}
	if _, err := DecodeRoster(append(encoded, 0)); err == nil {
		t.Fatal("trailing roster byte accepted")
	}
}

func FuzzVerifyArtifact(f *testing.F) {
	f.Add([]byte(`{"roster_hash":"00","members":[]}`))
	f.Add([]byte(`{}`))
	f.Fuzz(func(t *testing.T, data []byte) {
		_, _ = VerifyArtifact(data)
	})
}

func signedFixture(t *testing.T) Artifact {
	t.Helper()
	alice, err := sigcrypto.GenerateIdentityFrom(bytes.NewReader(bytes.Repeat([]byte{1}, 64)))
	if err != nil {
		t.Fatal(err)
	}
	defer alice.Zero()
	bob, err := sigcrypto.GenerateIdentityFrom(bytes.NewReader(bytes.Repeat([]byte{2}, 64)))
	if err != nil {
		t.Fatal(err)
	}
	defer bob.Zero()
	unsigned := []sigcrypto.CovenantMember{
		{Nick: "alice", PublicKey: alice.Public()},
		{Nick: "bob", PublicKey: bob.Public()},
	}
	hash, sorted, err := sigcrypto.CovenantRosterHash(unsigned)
	if err != nil {
		t.Fatal(err)
	}
	keys := map[sigcrypto.PublicKey]*sigcrypto.KeyPair{alice.Public(): &alice, bob.Public(): &bob}
	members := make([]SignedMember, len(sorted))
	for index, member := range sorted {
		signature, err := sigcrypto.SignCovenantRoster(keys[member.PublicKey], hash)
		if err != nil {
			t.Fatal(err)
		}
		members[index] = SignedMember{Nick: member.Nick, PublicKey: member.PublicKey, Signature: signature}
	}
	var session sigcrypto.Hash
	for index := range session {
		session[index] = byte(index)
	}
	return Artifact{
		Version: "0.2.0", GroupName: "friends", CreatedAt: 1234,
		SessionID: session, RosterHash: hash, Members: members, MemberCount: 2,
	}
}

func mustArtifact(t *testing.T, artifact Artifact) []byte {
	t.Helper()
	encoded, err := BuildArtifact(artifact)
	if err != nil {
		t.Fatal(err)
	}
	return encoded
}
