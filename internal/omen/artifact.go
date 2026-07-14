package omen

import (
	"bytes"
	"crypto/subtle"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"strconv"
	"unicode/utf8"

	"github.com/no-way-labs/cauldron/internal/frame"
	"github.com/no-way-labs/cauldron/internal/jsonstrict"
	"github.com/no-way-labs/cauldron/internal/sigcrypto"
)

const MaxArtifactBytes = 1 << 20

type Peer struct {
	Slot      byte
	Nick      string
	PublicKey sigcrypto.PublicKey
}

type Commitment struct {
	Slot       byte
	Commitment sigcrypto.Hash
	Signature  sigcrypto.Signature
}

type Reveal struct {
	Vote     byte
	Blinding [32]byte
}

type Artifact struct {
	Version       string
	SessionID     sigcrypto.Hash
	Timestamp     uint64
	Question      string
	Options       []string
	VoterCount    int
	RosterHash    sigcrypto.Hash
	Roster        []Peer
	Commitments   []Commitment
	Reveals       []Reveal
	Counts        []uint32
	Winner        string
	HostPublicKey sigcrypto.PublicKey
	HostSignature sigcrypto.Signature
}

type VerifyResult struct {
	Valid                     bool
	HostSignatureValid        bool
	RosterHashValid           bool
	CommitmentSignaturesValid bool
	RosterComplete            bool
	BijectionValid            bool
	TallyMatches              bool
	WinnerValid               bool

	Artifact
	// RevealSlots proves the v1 shuffle is linkable: each revealed preimage can
	// be mapped directly back to the commitment's roster slot.
	RevealSlots []byte
}

// BuildArtifact writes the exact Zig v1 JSON layout and signs the Blake2b-256
// hash of every byte preceding the top-level host_signature key.
func BuildArtifact(input Artifact, host *sigcrypto.KeyPair) ([]byte, error) {
	if host == nil {
		return nil, errors.New("omen: host identity is required")
	}
	input.HostPublicKey = host.Public()
	if err := validateForBuild(input); err != nil {
		return nil, err
	}
	var output bytes.Buffer
	output.Grow(512 + len(input.Roster)*320)
	output.WriteString(`{"omen_version":"`)
	appendEscaped(&output, input.Version)
	output.WriteString(`","session_id":"`)
	appendHex(&output, input.SessionID[:])
	output.WriteString(`","timestamp":`)
	output.WriteString(strconv.FormatUint(input.Timestamp, 10))
	output.WriteString(`,"question":"`)
	appendEscaped(&output, input.Question)
	output.WriteString(`","options":[`)
	for index, option := range input.Options {
		if index > 0 {
			output.WriteByte(',')
		}
		output.WriteByte('"')
		appendEscaped(&output, option)
		output.WriteByte('"')
	}
	output.WriteString(`],"voter_count":`)
	output.WriteString(strconv.Itoa(len(input.Roster)))
	output.WriteString(`,"roster_hash":"`)
	appendHex(&output, input.RosterHash[:])
	output.WriteString(`","roster":[`)
	for index, peer := range input.Roster {
		if index > 0 {
			output.WriteByte(',')
		}
		output.WriteString(`{"slot":`)
		output.WriteString(strconv.Itoa(int(peer.Slot)))
		output.WriteString(`,"nick":"`)
		appendEscaped(&output, peer.Nick)
		output.WriteString(`","pubkey":"`)
		appendHex(&output, peer.PublicKey[:])
		output.WriteString(`"}`)
	}
	output.WriteString(`],"commitments":[`)
	for index, commitment := range input.Commitments {
		if index > 0 {
			output.WriteByte(',')
		}
		output.WriteString(`{"slot":`)
		output.WriteString(strconv.Itoa(int(commitment.Slot)))
		output.WriteString(`,"commitment":"`)
		appendHex(&output, commitment.Commitment[:])
		output.WriteString(`","signature":"`)
		appendHex(&output, commitment.Signature[:])
		output.WriteString(`"}`)
	}
	output.WriteString(`],"reveals":[`)
	for index, reveal := range input.Reveals {
		if index > 0 {
			output.WriteByte(',')
		}
		output.WriteString(`{"vote":`)
		output.WriteString(strconv.Itoa(int(reveal.Vote)))
		output.WriteString(`,"blinding":"`)
		appendHex(&output, reveal.Blinding[:])
		output.WriteString(`"}`)
	}
	output.WriteString(`],"tally":{`)
	for index, option := range input.Options {
		if index > 0 {
			output.WriteByte(',')
		}
		output.WriteByte('"')
		appendEscaped(&output, option)
		output.WriteString(`":`)
		output.WriteString(strconv.FormatUint(uint64(input.Counts[index]), 10))
	}
	output.WriteString(`},"winner":"`)
	appendEscaped(&output, input.Winner)
	output.WriteString(`","host_pubkey":"`)
	appendHex(&output, input.HostPublicKey[:])
	output.WriteString(`",`)

	contentHash := sigcrypto.Blake256(output.Bytes())
	signature, err := host.Sign(contentHash[:])
	if err != nil {
		return nil, err
	}
	output.WriteString(`"host_signature":"`)
	appendHex(&output, signature[:])
	output.WriteString(`"}`)
	if output.Len() > frame.MaxPayloadLen {
		return nil, fmt.Errorf("omen: artifact is %d bytes, exceeding frame limit", output.Len())
	}
	result, err := VerifyArtifact(output.Bytes())
	if err != nil || !result.Valid {
		return nil, fmt.Errorf("omen: generated artifact failed self-verification: %w", err)
	}
	return output.Bytes(), nil
}

func VerifyArtifact(data []byte) (VerifyResult, error) {
	if len(data) > MaxArtifactBytes {
		return VerifyResult{}, errors.New("omen: artifact exceeds 1 MiB")
	}
	members, err := jsonstrict.TopLevelMembers(data)
	if err != nil {
		return VerifyResult{}, fmt.Errorf("omen: invalid JSON: %w", err)
	}
	if len(members) == 0 || members[len(members)-1].Key != "host_signature" {
		return VerifyResult{}, errors.New("omen: host_signature must be the final top-level member")
	}
	signatureOffset := members[len(members)-1].KeyOffset
	if signatureOffset+len(`"host_signature"`) > len(data) ||
		string(data[signatureOffset:signatureOffset+len(`"host_signature"`)]) != `"host_signature"` {
		return VerifyResult{}, errors.New("omen: host_signature key is not canonical")
	}

	var object map[string]json.RawMessage
	if err := json.Unmarshal(data, &object); err != nil {
		return VerifyResult{}, err
	}
	artifact, err := decodeArtifact(object)
	if err != nil {
		return VerifyResult{}, err
	}
	if err := validateStructure(artifact); err != nil {
		return VerifyResult{}, err
	}

	result := VerifyResult{Artifact: artifact, RosterComplete: true}
	recomputedRoster, err := rosterHash(artifact.Roster)
	if err != nil {
		return VerifyResult{}, err
	}
	result.RosterHashValid = subtle.ConstantTimeCompare(recomputedRoster[:], artifact.RosterHash[:]) == 1
	result.CommitmentSignaturesValid = true
	for index, commitment := range artifact.Commitments {
		peer := artifact.Roster[index]
		if !sigcrypto.VerifyOmenCommitment(peer.PublicKey, recomputedRoster, commitment.Commitment, commitment.Signature) {
			result.CommitmentSignaturesValid = false
			break
		}
	}
	result.RevealSlots, result.BijectionValid = matchReveals(artifact.Reveals, artifact.Commitments)
	computedCounts := ComputeTally(artifact.Reveals, len(artifact.Options))
	result.TallyMatches = equalCounts(computedCounts, artifact.Counts)
	result.WinnerValid = artifact.Winner == ComputeWinner(artifact.Options, computedCounts)
	contentHash := sigcrypto.Blake256(data[:signatureOffset])
	result.HostSignatureValid = sigcrypto.Verify(artifact.HostPublicKey, contentHash[:], artifact.HostSignature)
	result.Valid = result.HostSignatureValid && result.RosterHashValid &&
		result.CommitmentSignaturesValid && result.RosterComplete && result.BijectionValid &&
		result.TallyMatches && result.WinnerValid
	return result, nil
}

func validateForBuild(artifact Artifact) error {
	if err := validateStructure(artifact); err != nil {
		return err
	}
	recomputed, err := rosterHash(artifact.Roster)
	if err != nil {
		return err
	}
	if recomputed != artifact.RosterHash {
		return errors.New("omen: roster hash does not match roster")
	}
	for index, commitment := range artifact.Commitments {
		if !sigcrypto.VerifyOmenCommitment(artifact.Roster[index].PublicKey, recomputed, commitment.Commitment, commitment.Signature) {
			return fmt.Errorf("omen: invalid commitment signature at slot %d", index)
		}
	}
	if _, valid := matchReveals(artifact.Reveals, artifact.Commitments); !valid {
		return errors.New("omen: reveals do not form a commitment bijection")
	}
	counts := ComputeTally(artifact.Reveals, len(artifact.Options))
	if !equalCounts(counts, artifact.Counts) {
		return errors.New("omen: tally does not match reveals")
	}
	if artifact.Winner != ComputeWinner(artifact.Options, counts) {
		return errors.New("omen: winner does not match tally")
	}
	return nil
}

func validateStructure(artifact Artifact) error {
	if artifact.Version == "" || !utf8.ValidString(artifact.Version) {
		return errors.New("omen: invalid version")
	}
	if len(artifact.Question) == 0 || len(artifact.Question) > 65535 || !utf8.ValidString(artifact.Question) {
		return errors.New("omen: question must be non-empty valid UTF-8 within u16 length")
	}
	if len(artifact.Options) < 2 || len(artifact.Options) > 255 {
		return errors.New("omen: option count must be 2..255")
	}
	optionSet := make(map[string]struct{}, len(artifact.Options))
	for _, option := range artifact.Options {
		if option == "" || len(option) > 65535 || !utf8.ValidString(option) {
			return errors.New("omen: options must be non-empty valid UTF-8 within u16 length")
		}
		if _, duplicate := optionSet[option]; duplicate {
			return errors.New("omen: duplicate option name")
		}
		optionSet[option] = struct{}{}
	}
	if len(artifact.Roster) < 2 || len(artifact.Roster) > 255 || artifact.VoterCount != len(artifact.Roster) {
		return errors.New("omen: voter_count must match a roster of 2..255 peers")
	}
	keys := make(map[sigcrypto.PublicKey]struct{}, len(artifact.Roster))
	for index, peer := range artifact.Roster {
		if int(peer.Slot) != index {
			return errors.New("omen: roster slots must be contiguous and canonical")
		}
		if peer.Nick == "" || len(peer.Nick) > frame.MaxSenderLen || !utf8.ValidString(peer.Nick) {
			return errors.New("omen: invalid roster nick")
		}
		if _, duplicate := keys[peer.PublicKey]; duplicate {
			return errors.New("omen: duplicate roster public key")
		}
		keys[peer.PublicKey] = struct{}{}
	}
	if artifact.HostPublicKey != artifact.Roster[0].PublicKey {
		return errors.New("omen: host_pubkey is not roster slot 0")
	}
	if len(artifact.Commitments) != len(artifact.Roster) {
		return errors.New("omen: commitment count does not match roster")
	}
	for index, commitment := range artifact.Commitments {
		if int(commitment.Slot) != index {
			return errors.New("omen: commitments do not have exact canonical slot coverage")
		}
	}
	if len(artifact.Reveals) != len(artifact.Commitments) {
		return errors.New("omen: reveal count does not match commitments")
	}
	for _, reveal := range artifact.Reveals {
		if int(reveal.Vote) >= len(artifact.Options) {
			return errors.New("omen: reveal vote index is outside options")
		}
	}
	if len(artifact.Counts) != len(artifact.Options) {
		return errors.New("omen: tally does not cover every option exactly")
	}
	return nil
}

func VerifyCommitSet(commitments []Commitment, setHash sigcrypto.Hash, roster []Peer, rosterHash sigcrypto.Hash, ownSlot *byte, ownCommitment *sigcrypto.Hash) error {
	if len(commitments) != len(roster) {
		return errors.New("omen: commitment set does not cover roster")
	}
	converted := make([]sigcrypto.OmenCommitment, len(commitments))
	for index, commitment := range commitments {
		if int(commitment.Slot) != index || int(roster[index].Slot) != index {
			return errors.New("omen: commitment set slots are not canonical")
		}
		if !sigcrypto.VerifyOmenCommitment(roster[index].PublicKey, rosterHash, commitment.Commitment, commitment.Signature) {
			return errors.New("omen: invalid commitment signature")
		}
		converted[index] = sigcrypto.OmenCommitment{Slot: commitment.Slot, Commitment: commitment.Commitment, Signature: commitment.Signature}
	}
	if sigcrypto.OmenCommitSetHash(converted) != setHash {
		return errors.New("omen: commitment set hash mismatch")
	}
	if ownSlot != nil && ownCommitment != nil {
		if int(*ownSlot) >= len(commitments) || commitments[*ownSlot].Commitment != *ownCommitment {
			return errors.New("omen: own commitment missing or modified")
		}
	}
	return nil
}

func ComputeTally(reveals []Reveal, optionCount int) []uint32 {
	counts := make([]uint32, optionCount)
	for _, reveal := range reveals {
		if int(reveal.Vote) < len(counts) {
			counts[reveal.Vote]++
		}
	}
	return counts
}

func ComputeWinner(options []string, counts []uint32) string {
	var max uint32
	winner := -1
	for index, count := range counts {
		if count > max {
			max, winner = count, index
		}
	}
	if winner < 0 || winner >= len(options) {
		return ""
	}
	return options[winner]
}

func matchReveals(reveals []Reveal, commitments []Commitment) ([]byte, bool) {
	if len(reveals) != len(commitments) {
		return nil, false
	}
	matched := make([]bool, len(commitments))
	slots := make([]byte, len(reveals))
	for revealIndex, reveal := range reveals {
		computed := sigcrypto.MakeCommitment(reveal.Vote, reveal.Blinding)
		found := -1
		for commitmentIndex, commitment := range commitments {
			if !matched[commitmentIndex] && commitment.Commitment == computed {
				found = commitmentIndex
				break
			}
		}
		if found < 0 {
			return nil, false
		}
		matched[found] = true
		slots[revealIndex] = commitments[found].Slot
	}
	return slots, true
}

func rosterHash(roster []Peer) (sigcrypto.Hash, error) {
	converted := make([]sigcrypto.OmenPeer, len(roster))
	for index, peer := range roster {
		converted[index] = sigcrypto.OmenPeer{Slot: peer.Slot, Nick: peer.Nick, PublicKey: peer.PublicKey}
	}
	return sigcrypto.OmenRosterHash(converted)
}

func decodeArtifact(object map[string]json.RawMessage) (Artifact, error) {
	var artifact Artifact
	var err error
	if artifact.Version, err = exactString(object, "omen_version"); err != nil {
		return Artifact{}, errors.New("omen: missing or invalid omen_version")
	}
	if artifact.SessionID, err = exactHash(object, "session_id"); err != nil {
		return Artifact{}, fmt.Errorf("omen: invalid session_id: %w", err)
	}
	if artifact.Timestamp, err = exactUint64(object, "timestamp"); err != nil {
		return Artifact{}, errors.New("omen: missing or invalid timestamp")
	}
	if artifact.Question, err = exactString(object, "question"); err != nil {
		return Artifact{}, errors.New("omen: missing or invalid question")
	}
	if err := exactDecode(object, "options", &artifact.Options); err != nil {
		return Artifact{}, errors.New("omen: missing or invalid options")
	}
	voterCount, err := exactUint64(object, "voter_count")
	if err != nil || voterCount > 255 {
		return Artifact{}, errors.New("omen: invalid voter_count")
	}
	artifact.VoterCount = int(voterCount)
	if artifact.RosterHash, err = exactHash(object, "roster_hash"); err != nil {
		return Artifact{}, fmt.Errorf("omen: invalid roster_hash: %w", err)
	}
	if artifact.Roster, err = decodeRoster(object); err != nil {
		return Artifact{}, err
	}
	if artifact.Commitments, err = decodeCommitments(object); err != nil {
		return Artifact{}, err
	}
	if artifact.Reveals, err = decodeReveals(object); err != nil {
		return Artifact{}, err
	}
	var tally map[string]uint32
	if err := exactDecode(object, "tally", &tally); err != nil {
		return Artifact{}, errors.New("omen: invalid tally")
	}
	if len(tally) != len(artifact.Options) {
		return Artifact{}, errors.New("omen: tally has missing or extra options")
	}
	artifact.Counts = make([]uint32, len(artifact.Options))
	for index, option := range artifact.Options {
		count, exists := tally[option]
		if !exists {
			return Artifact{}, errors.New("omen: tally is missing an option")
		}
		artifact.Counts[index] = count
	}
	if artifact.Winner, err = exactString(object, "winner"); err != nil {
		return Artifact{}, errors.New("omen: invalid winner")
	}
	if artifact.HostPublicKey, err = exactPublicKey(object, "host_pubkey"); err != nil {
		return Artifact{}, errors.New("omen: invalid host_pubkey")
	}
	if artifact.HostSignature, err = exactSignature(object, "host_signature"); err != nil {
		return Artifact{}, errors.New("omen: invalid host_signature")
	}
	return artifact, nil
}

func decodeRoster(object map[string]json.RawMessage) ([]Peer, error) {
	var raw []map[string]json.RawMessage
	if err := exactDecode(object, "roster", &raw); err != nil {
		return nil, errors.New("omen: invalid roster")
	}
	result := make([]Peer, len(raw))
	for index, item := range raw {
		slot, err := exactUint64(item, "slot")
		if err != nil || slot > 255 {
			return nil, errors.New("omen: invalid roster slot")
		}
		nick, err := exactString(item, "nick")
		if err != nil {
			return nil, errors.New("omen: invalid roster nick")
		}
		public, err := exactPublicKey(item, "pubkey")
		if err != nil {
			return nil, errors.New("omen: invalid roster pubkey")
		}
		result[index] = Peer{Slot: byte(slot), Nick: nick, PublicKey: public}
	}
	return result, nil
}

func decodeCommitments(object map[string]json.RawMessage) ([]Commitment, error) {
	var raw []map[string]json.RawMessage
	if err := exactDecode(object, "commitments", &raw); err != nil {
		return nil, errors.New("omen: invalid commitments")
	}
	result := make([]Commitment, len(raw))
	for index, item := range raw {
		slot, err := exactUint64(item, "slot")
		if err != nil || slot > 255 {
			return nil, errors.New("omen: invalid commitment slot")
		}
		commitment, err := exactHash(item, "commitment")
		if err != nil {
			return nil, errors.New("omen: invalid commitment hash")
		}
		signature, err := exactSignature(item, "signature")
		if err != nil {
			return nil, errors.New("omen: invalid commitment signature")
		}
		result[index] = Commitment{Slot: byte(slot), Commitment: commitment, Signature: signature}
	}
	return result, nil
}

func decodeReveals(object map[string]json.RawMessage) ([]Reveal, error) {
	var raw []map[string]json.RawMessage
	if err := exactDecode(object, "reveals", &raw); err != nil {
		return nil, errors.New("omen: invalid reveals")
	}
	result := make([]Reveal, len(raw))
	for index, item := range raw {
		vote, err := exactUint64(item, "vote")
		if err != nil || vote > 255 {
			return nil, errors.New("omen: invalid reveal vote")
		}
		blinding, err := exactHash(item, "blinding")
		if err != nil {
			return nil, errors.New("omen: invalid reveal blinding")
		}
		result[index] = Reveal{Vote: byte(vote), Blinding: [32]byte(blinding)}
	}
	return result, nil
}

func exactDecode(object map[string]json.RawMessage, field string, target any) error {
	raw, exists := object[field]
	if !exists {
		return errors.New("missing field")
	}
	return json.Unmarshal(raw, target)
}

func exactString(object map[string]json.RawMessage, field string) (string, error) {
	var value string
	err := exactDecode(object, field, &value)
	return value, err
}

func exactUint64(object map[string]json.RawMessage, field string) (uint64, error) {
	var value uint64
	err := exactDecode(object, field, &value)
	return value, err
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
		return sigcrypto.PublicKey{}, errors.New("expected public key hex")
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
		return sigcrypto.Signature{}, errors.New("expected signature hex")
	}
	var result sigcrypto.Signature
	copy(result[:], decoded)
	return result, nil
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

func equalCounts(first, second []uint32) bool {
	if len(first) != len(second) {
		return false
	}
	for index := range first {
		if first[index] != second[index] {
			return false
		}
	}
	return true
}
