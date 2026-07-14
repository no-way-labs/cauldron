package covenant

import (
	"bytes"
	"crypto/subtle"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"sort"
	"strconv"
	"unicode/utf8"

	"github.com/no-way-labs/cauldron/internal/frame"
	"github.com/no-way-labs/cauldron/internal/jsonstrict"
	"github.com/no-way-labs/cauldron/internal/sigcrypto"
)

const (
	MinMembers       = 2
	MaxMembers       = 255
	MaxArtifactBytes = 1 << 20
)

type SignedMember struct {
	Nick      string
	PublicKey sigcrypto.PublicKey
	Signature sigcrypto.Signature
}

type Artifact struct {
	Version     string
	GroupName   string
	CreatedAt   uint64
	SessionID   sigcrypto.Hash
	RosterHash  sigcrypto.Hash
	Members     []SignedMember
	MemberCount int
}

type MemberResult struct {
	SignedMember
	Valid bool
}

type VerifyResult struct {
	Valid       bool
	Version     string
	GroupName   string
	CreatedAt   uint64
	SessionID   sigcrypto.Hash
	RosterHash  sigcrypto.Hash
	MemberCount int
	Members     []MemberResult
}

// BuildArtifact mirrors the canonical Zig writer byte-for-byte: fixed key
// order, no insignificant whitespace, lowercase hex, and custom escaping.
func BuildArtifact(artifact Artifact) ([]byte, error) {
	if artifact.Version == "" || !utf8.ValidString(artifact.Version) {
		return nil, errors.New("covenant: invalid version")
	}
	if !utf8.ValidString(artifact.GroupName) {
		return nil, errors.New("covenant: invalid group name")
	}
	if len(artifact.Members) < MinMembers || len(artifact.Members) > MaxMembers {
		return nil, fmt.Errorf("covenant: member count must be %d..%d", MinMembers, MaxMembers)
	}
	if artifact.MemberCount != 0 && artifact.MemberCount != len(artifact.Members) {
		return nil, errors.New("covenant: stale member count")
	}
	canonical, err := CanonicalSignedMembers(artifact.Members)
	if err != nil {
		return nil, err
	}
	hashMembers := make([]sigcrypto.CovenantMember, len(canonical))
	for index, member := range artifact.Members {
		if err := validateNick(member.Nick); err != nil {
			return nil, err
		}
		if member.PublicKey != canonical[index].PublicKey {
			return nil, errors.New("covenant: members are not in canonical public-key order")
		}
		hashMembers[index] = sigcrypto.CovenantMember{Nick: member.Nick, PublicKey: member.PublicKey}
	}
	recomputed, _, err := sigcrypto.CovenantRosterHash(hashMembers)
	if err != nil {
		return nil, err
	}
	if subtle.ConstantTimeCompare(recomputed[:], artifact.RosterHash[:]) != 1 {
		return nil, errors.New("covenant: roster hash does not match members")
	}
	for _, member := range artifact.Members {
		if !sigcrypto.VerifyCovenantRoster(member.PublicKey, recomputed, member.Signature) {
			return nil, fmt.Errorf("covenant: invalid signature for %s", member.Nick)
		}
	}

	var output bytes.Buffer
	output.Grow(256 + len(artifact.Members)*256)
	output.WriteString(`{"covenant_version":"`)
	appendEscaped(&output, artifact.Version)
	output.WriteString(`","group_name":"`)
	appendEscaped(&output, artifact.GroupName)
	output.WriteString(`","created_at":`)
	output.WriteString(strconv.FormatUint(artifact.CreatedAt, 10))
	output.WriteString(`,"session_id":"`)
	appendHex(&output, artifact.SessionID[:])
	output.WriteString(`","roster_hash":"`)
	appendHex(&output, artifact.RosterHash[:])
	output.WriteString(`","members":[`)
	for index, member := range artifact.Members {
		if index > 0 {
			output.WriteByte(',')
		}
		output.WriteString(`{"nick":"`)
		appendEscaped(&output, member.Nick)
		output.WriteString(`","pubkey":"`)
		appendHex(&output, member.PublicKey[:])
		output.WriteString(`","signature":"`)
		appendHex(&output, member.Signature[:])
		output.WriteString(`"}`)
	}
	output.WriteString(`],"member_count":`)
	output.WriteString(strconv.Itoa(len(artifact.Members)))
	output.WriteByte('}')
	if output.Len() > MaxArtifactBytes || output.Len() > frame.MaxPayloadLen {
		return nil, fmt.Errorf("covenant: artifact is %d bytes, exceeds frame limit", output.Len())
	}
	return output.Bytes(), nil
}

// VerifyArtifact performs strict structural and semantic verification. The v1
// signatures authenticate the roster only; metadata fields remain unbound.
func VerifyArtifact(data []byte) (VerifyResult, error) {
	if len(data) > MaxArtifactBytes {
		return VerifyResult{}, errors.New("covenant: artifact exceeds 1 MiB")
	}
	if err := jsonstrict.Validate(data); err != nil {
		return VerifyResult{}, fmt.Errorf("covenant: invalid JSON: %w", err)
	}
	var object map[string]json.RawMessage
	if err := json.Unmarshal(data, &object); err != nil {
		return VerifyResult{}, fmt.Errorf("covenant: decode object: %w", err)
	}
	version, err := exactString(object, "covenant_version")
	if err != nil || version == "" {
		return VerifyResult{}, errors.New("covenant: missing or invalid covenant_version")
	}
	groupName, err := exactString(object, "group_name")
	if err != nil {
		return VerifyResult{}, errors.New("covenant: missing or invalid group_name")
	}
	createdAt, err := exactUint64(object, "created_at")
	if err != nil {
		return VerifyResult{}, errors.New("covenant: missing or invalid created_at")
	}
	sessionID, err := exactHash(object, "session_id")
	if err != nil {
		return VerifyResult{}, fmt.Errorf("covenant: invalid session_id: %w", err)
	}
	statedHash, err := exactHash(object, "roster_hash")
	if err != nil {
		return VerifyResult{}, fmt.Errorf("covenant: invalid roster_hash: %w", err)
	}
	memberCount, err := exactUint64(object, "member_count")
	if err != nil || memberCount < MinMembers || memberCount > MaxMembers {
		return VerifyResult{}, fmt.Errorf("covenant: member_count must be %d..%d", MinMembers, MaxMembers)
	}
	rawMembers, exists := object["members"]
	if !exists {
		return VerifyResult{}, errors.New("covenant: missing members")
	}
	var encodedMembers []json.RawMessage
	if err := json.Unmarshal(rawMembers, &encodedMembers); err != nil {
		return VerifyResult{}, errors.New("covenant: members must be an array")
	}
	if len(encodedMembers) != int(memberCount) {
		return VerifyResult{}, errors.New("covenant: member_count does not match members array")
	}

	members := make([]SignedMember, len(encodedMembers))
	for index, encoded := range encodedMembers {
		var memberObject map[string]json.RawMessage
		if err := json.Unmarshal(encoded, &memberObject); err != nil {
			return VerifyResult{}, fmt.Errorf("covenant: member %d must be an object", index)
		}
		nick, err := exactString(memberObject, "nick")
		if err != nil {
			return VerifyResult{}, fmt.Errorf("covenant: member %d has invalid nick", index)
		}
		if err := validateNick(nick); err != nil {
			return VerifyResult{}, fmt.Errorf("covenant: member %d: %w", index, err)
		}
		public, err := exactPublicKey(memberObject, "pubkey")
		if err != nil {
			return VerifyResult{}, fmt.Errorf("covenant: member %d has invalid pubkey: %w", index, err)
		}
		signature, err := exactSignature(memberObject, "signature")
		if err != nil {
			return VerifyResult{}, fmt.Errorf("covenant: member %d has invalid signature: %w", index, err)
		}
		members[index] = SignedMember{Nick: nick, PublicKey: public, Signature: signature}
	}
	hashMembers := make([]sigcrypto.CovenantMember, len(members))
	for index, member := range members {
		hashMembers[index] = sigcrypto.CovenantMember{Nick: member.Nick, PublicKey: member.PublicKey}
	}
	recomputed, sortedMembers, err := sigcrypto.CovenantRosterHash(hashMembers)
	if err != nil {
		return VerifyResult{}, fmt.Errorf("covenant: invalid roster: %w", err)
	}
	for index := range members {
		if members[index].PublicKey != sortedMembers[index].PublicKey {
			return VerifyResult{}, errors.New("covenant: members are not in canonical public-key order")
		}
	}
	if subtle.ConstantTimeCompare(recomputed[:], statedHash[:]) != 1 {
		return VerifyResult{}, errors.New("covenant: roster_hash does not match members")
	}
	result := VerifyResult{
		Valid: true, Version: version, GroupName: groupName, CreatedAt: createdAt,
		SessionID: sessionID, RosterHash: recomputed, MemberCount: len(members),
		Members: make([]MemberResult, len(members)),
	}
	for index, member := range members {
		valid := sigcrypto.VerifyCovenantRoster(member.PublicKey, recomputed, member.Signature)
		result.Members[index] = MemberResult{SignedMember: member, Valid: valid}
		result.Valid = result.Valid && valid
	}
	return result, nil
}

func CanonicalSignedMembers(members []SignedMember) ([]SignedMember, error) {
	result := append([]SignedMember(nil), members...)
	sort.Slice(result, func(i, j int) bool {
		return bytes.Compare(result[i].PublicKey[:], result[j].PublicKey[:]) < 0
	})
	for index, member := range result {
		if err := validateNick(member.Nick); err != nil {
			return nil, err
		}
		if index > 0 && result[index-1].PublicKey == member.PublicKey {
			return nil, errors.New("covenant: duplicate public key")
		}
	}
	return result, nil
}

func validateNick(nick string) error {
	if nick == "" || len(nick) > frame.MaxSenderLen || !utf8.ValidString(nick) {
		return fmt.Errorf("nick must be non-empty valid UTF-8 and at most %d bytes", frame.MaxSenderLen)
	}
	return nil
}

func appendEscaped(output *bytes.Buffer, value string) {
	const digits = "0123456789abcdef"
	for _, character := range []byte(value) {
		switch character {
		case '"':
			output.WriteString(`\"`)
		case '\\':
			output.WriteString(`\\`)
		case '\n':
			output.WriteString(`\n`)
		case '\r':
			output.WriteString(`\r`)
		case '\t':
			output.WriteString(`\t`)
		default:
			if character < 0x20 {
				output.WriteString(`\u00`)
				output.WriteByte(digits[character>>4])
				output.WriteByte(digits[character&0x0f])
			} else {
				output.WriteByte(character)
			}
		}
	}
}

func appendHex(output *bytes.Buffer, value []byte) {
	encoded := make([]byte, hex.EncodedLen(len(value)))
	hex.Encode(encoded, value)
	output.Write(encoded)
}

func exactString(object map[string]json.RawMessage, field string) (string, error) {
	raw, exists := object[field]
	if !exists {
		return "", errors.New("missing field")
	}
	var value string
	if err := json.Unmarshal(raw, &value); err != nil {
		return "", err
	}
	return value, nil
}

func exactUint64(object map[string]json.RawMessage, field string) (uint64, error) {
	raw, exists := object[field]
	if !exists {
		return 0, errors.New("missing field")
	}
	var value uint64
	if err := json.Unmarshal(raw, &value); err != nil {
		return 0, err
	}
	return value, nil
}

func exactHash(object map[string]json.RawMessage, field string) (sigcrypto.Hash, error) {
	value, err := exactString(object, field)
	if err != nil {
		return sigcrypto.Hash{}, err
	}
	decoded, err := hex.DecodeString(value)
	if err != nil || len(decoded) != sigcrypto.HashSize {
		return sigcrypto.Hash{}, errors.New("expected 64 hexadecimal characters")
	}
	var result sigcrypto.Hash
	copy(result[:], decoded)
	return result, nil
}

func exactPublicKey(object map[string]json.RawMessage, field string) (sigcrypto.PublicKey, error) {
	value, err := exactString(object, field)
	if err != nil {
		return sigcrypto.PublicKey{}, err
	}
	decoded, err := hex.DecodeString(value)
	if err != nil || len(decoded) != sigcrypto.PublicKeySize {
		return sigcrypto.PublicKey{}, errors.New("expected 64 hexadecimal characters")
	}
	var result sigcrypto.PublicKey
	copy(result[:], decoded)
	return result, nil
}

func exactSignature(object map[string]json.RawMessage, field string) (sigcrypto.Signature, error) {
	value, err := exactString(object, field)
	if err != nil {
		return sigcrypto.Signature{}, err
	}
	decoded, err := hex.DecodeString(value)
	if err != nil || len(decoded) != sigcrypto.SignatureSize {
		return sigcrypto.Signature{}, errors.New("expected 128 hexadecimal characters")
	}
	var result sigcrypto.Signature
	copy(result[:], decoded)
	return result, nil
}
