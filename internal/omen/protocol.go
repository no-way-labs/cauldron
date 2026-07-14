package omen

import (
	"bytes"
	"encoding/binary"
	"errors"
	"fmt"
	"unicode/utf8"

	"github.com/no-way-labs/cauldron/internal/frame"
	"github.com/no-way-labs/cauldron/internal/sigcrypto"
)

const Magic = "OMEN_HELLO"

const (
	MessageJoin       byte = 1
	MessageLeave      byte = 3
	MessagePublicKey  byte = 10
	MessageBallot     byte = 11
	MessagePeerList   byte = 12
	MessagePhase      byte = 13
	MessageCommitment byte = 14
	MessageCommitSet  byte = 15
	MessageReveal     byte = 16
	MessageRevealSet  byte = 17
	MessageTally      byte = 18
	MessageAbort      byte = 19
)

const (
	PhaseLobby byte = iota
	PhaseCommit
	PhaseReveal
	PhaseTally
	PhaseDone
)

func ValidMessageType(value byte) bool {
	switch value {
	case MessageJoin, MessageLeave, MessagePublicKey, MessageBallot,
		MessagePeerList, MessagePhase, MessageCommitment, MessageCommitSet,
		MessageReveal, MessageRevealSet, MessageTally, MessageAbort:
		return true
	default:
		return false
	}
}

type Ballot struct {
	SessionID sigcrypto.Hash
	Question  string
	Options   []string
}

func EncodeBallot(ballot Ballot) ([]byte, error) {
	if err := validateBallot(ballot); err != nil {
		return nil, err
	}
	length := sigcrypto.HashSize + 2 + len(ballot.Question) + 1
	for _, option := range ballot.Options {
		length += 2 + len(option)
	}
	if length > frame.MaxPayloadLen {
		return nil, frame.ErrPayload
	}
	output := make([]byte, 0, length)
	output = append(output, ballot.SessionID[:]...)
	output = binary.BigEndian.AppendUint16(output, uint16(len(ballot.Question)))
	output = append(output, ballot.Question...)
	output = append(output, byte(len(ballot.Options)))
	for _, option := range ballot.Options {
		output = binary.BigEndian.AppendUint16(output, uint16(len(option)))
		output = append(output, option...)
	}
	return output, nil
}

func DecodeBallot(data []byte) (Ballot, error) {
	if len(data) < sigcrypto.HashSize+3 || len(data) > frame.MaxPayloadLen {
		return Ballot{}, errors.New("omen: invalid ballot payload length")
	}
	var ballot Ballot
	copy(ballot.SessionID[:], data[:sigcrypto.HashSize])
	position := sigcrypto.HashSize
	questionLength := int(binary.BigEndian.Uint16(data[position : position+2]))
	position += 2
	if questionLength == 0 || position+questionLength >= len(data) {
		return Ballot{}, errors.New("omen: invalid ballot question length")
	}
	question := data[position : position+questionLength]
	if !utf8.Valid(question) {
		return Ballot{}, errors.New("omen: ballot question is invalid UTF-8")
	}
	ballot.Question = string(question)
	position += questionLength
	optionCount := int(data[position])
	position++
	if optionCount < 2 {
		return Ballot{}, errors.New("omen: ballot must contain at least two options")
	}
	ballot.Options = make([]string, optionCount)
	seen := make(map[string]struct{}, optionCount)
	for index := range ballot.Options {
		if position+2 > len(data) {
			return Ballot{}, errors.New("omen: truncated ballot option length")
		}
		optionLength := int(binary.BigEndian.Uint16(data[position : position+2]))
		position += 2
		if optionLength == 0 || position+optionLength > len(data) {
			return Ballot{}, errors.New("omen: invalid ballot option length")
		}
		option := data[position : position+optionLength]
		if !utf8.Valid(option) {
			return Ballot{}, errors.New("omen: ballot option is invalid UTF-8")
		}
		ballot.Options[index] = string(option)
		if _, duplicate := seen[ballot.Options[index]]; duplicate {
			return Ballot{}, errors.New("omen: ballot options must be unique")
		}
		seen[ballot.Options[index]] = struct{}{}
		position += optionLength
	}
	if position != len(data) {
		return Ballot{}, errors.New("omen: trailing ballot bytes")
	}
	return ballot, nil
}

func validateBallot(ballot Ballot) error {
	if ballot.Question == "" || len(ballot.Question) > 65535 || !utf8.ValidString(ballot.Question) {
		return errors.New("omen: question must be non-empty valid UTF-8 within u16 length")
	}
	if len(ballot.Options) < 2 || len(ballot.Options) > 255 {
		return errors.New("omen: option count must be 2..255")
	}
	seen := make(map[string]struct{}, len(ballot.Options))
	for _, option := range ballot.Options {
		if option == "" || len(option) > 65535 || !utf8.ValidString(option) {
			return errors.New("omen: options must be non-empty valid UTF-8 within u16 length")
		}
		if _, duplicate := seen[option]; duplicate {
			return errors.New("omen: options must be unique")
		}
		seen[option] = struct{}{}
	}
	return nil
}

func EncodePeerList(peers []Peer) ([]byte, error) {
	if err := validatePeers(peers); err != nil {
		return nil, err
	}
	length := 1
	for _, peer := range peers {
		length += 2 + len(peer.Nick) + sigcrypto.PublicKeySize
	}
	if length > frame.MaxPayloadLen {
		return nil, frame.ErrPayload
	}
	output := make([]byte, 1, length)
	output[0] = byte(len(peers))
	for _, peer := range peers {
		output = append(output, peer.Slot, byte(len(peer.Nick)))
		output = append(output, peer.Nick...)
		output = append(output, peer.PublicKey[:]...)
	}
	return output, nil
}

func DecodePeerList(data []byte) ([]Peer, error) {
	if len(data) < 1 || len(data) > frame.MaxPayloadLen {
		return nil, errors.New("omen: invalid peer-list payload length")
	}
	count := int(data[0])
	if count < 2 {
		return nil, errors.New("omen: peer list must contain at least two peers")
	}
	position := 1
	peers := make([]Peer, count)
	for index := range peers {
		if position+2 > len(data) {
			return nil, errors.New("omen: truncated peer-list entry")
		}
		peers[index].Slot = data[position]
		nickLength := int(data[position+1])
		position += 2
		if nickLength == 0 || nickLength > frame.MaxSenderLen || position+nickLength+sigcrypto.PublicKeySize > len(data) {
			return nil, errors.New("omen: invalid peer-list nick length")
		}
		nick := data[position : position+nickLength]
		if !utf8.Valid(nick) {
			return nil, errors.New("omen: peer-list nick is invalid UTF-8")
		}
		peers[index].Nick = string(nick)
		position += nickLength
		copy(peers[index].PublicKey[:], data[position:position+sigcrypto.PublicKeySize])
		position += sigcrypto.PublicKeySize
	}
	if position != len(data) {
		return nil, errors.New("omen: trailing peer-list bytes")
	}
	if err := validatePeers(peers); err != nil {
		return nil, err
	}
	return peers, nil
}

func validatePeers(peers []Peer) error {
	if len(peers) < 2 || len(peers) > 255 {
		return errors.New("omen: peer count must be 2..255")
	}
	keys := make(map[sigcrypto.PublicKey]struct{}, len(peers))
	nicks := make(map[string]struct{}, len(peers))
	for index, peer := range peers {
		if int(peer.Slot) != index {
			return errors.New("omen: peer slots must be contiguous and canonical")
		}
		if peer.Nick == "" || len(peer.Nick) > frame.MaxSenderLen || !utf8.ValidString(peer.Nick) {
			return fmt.Errorf("omen: invalid nick at slot %d", index)
		}
		if _, duplicate := keys[peer.PublicKey]; duplicate {
			return errors.New("omen: duplicate peer public key")
		}
		keys[peer.PublicKey] = struct{}{}
		if _, duplicate := nicks[peer.Nick]; duplicate {
			return errors.New("omen: duplicate resolved peer nick")
		}
		nicks[peer.Nick] = struct{}{}
	}
	return nil
}

func EncodePhase(phase byte, rosterHash sigcrypto.Hash) ([]byte, error) {
	if phase > PhaseDone {
		return nil, errors.New("omen: invalid phase")
	}
	output := make([]byte, 1+sigcrypto.HashSize)
	output[0] = phase
	copy(output[1:], rosterHash[:])
	return output, nil
}

func DecodePhase(data []byte) (byte, sigcrypto.Hash, error) {
	if len(data) != 1+sigcrypto.HashSize || data[0] > PhaseDone {
		return 0, sigcrypto.Hash{}, errors.New("omen: invalid phase payload")
	}
	var rosterHash sigcrypto.Hash
	copy(rosterHash[:], data[1:])
	return data[0], rosterHash, nil
}

func EncodeCommitment(commitment Commitment) []byte {
	output := make([]byte, 0, sigcrypto.HashSize+sigcrypto.SignatureSize)
	output = append(output, commitment.Commitment[:]...)
	output = append(output, commitment.Signature[:]...)
	return output
}

func DecodeCommitment(data []byte, slot byte) (Commitment, error) {
	if len(data) != sigcrypto.HashSize+sigcrypto.SignatureSize {
		return Commitment{}, errors.New("omen: invalid commitment payload")
	}
	result := Commitment{Slot: slot}
	copy(result.Commitment[:], data[:sigcrypto.HashSize])
	copy(result.Signature[:], data[sigcrypto.HashSize:])
	return result, nil
}

func EncodeCommitSet(commitments []Commitment, setHash sigcrypto.Hash) ([]byte, error) {
	if len(commitments) < 2 || len(commitments) > 255 {
		return nil, errors.New("omen: commitment count must be 2..255")
	}
	output := make([]byte, 1, 1+len(commitments)*(1+sigcrypto.HashSize+sigcrypto.SignatureSize)+sigcrypto.HashSize)
	output[0] = byte(len(commitments))
	for index, commitment := range commitments {
		if int(commitment.Slot) != index {
			return nil, errors.New("omen: commitment slots must be contiguous and canonical")
		}
		output = append(output, commitment.Slot)
		output = append(output, commitment.Commitment[:]...)
		output = append(output, commitment.Signature[:]...)
	}
	output = append(output, setHash[:]...)
	if len(output) > frame.MaxPayloadLen {
		return nil, frame.ErrPayload
	}
	return output, nil
}

func DecodeCommitSet(data []byte) ([]Commitment, sigcrypto.Hash, error) {
	if len(data) < 1 || len(data) > frame.MaxPayloadLen {
		return nil, sigcrypto.Hash{}, errors.New("omen: invalid commitment-set payload length")
	}
	count := int(data[0])
	expected := 1 + count*(1+sigcrypto.HashSize+sigcrypto.SignatureSize) + sigcrypto.HashSize
	if count < 2 || len(data) != expected {
		return nil, sigcrypto.Hash{}, errors.New("omen: invalid commitment-set length")
	}
	position := 1
	commitments := make([]Commitment, count)
	for index := range commitments {
		commitments[index].Slot = data[position]
		position++
		if int(commitments[index].Slot) != index {
			return nil, sigcrypto.Hash{}, errors.New("omen: commitment-set slots are not canonical")
		}
		copy(commitments[index].Commitment[:], data[position:position+sigcrypto.HashSize])
		position += sigcrypto.HashSize
		copy(commitments[index].Signature[:], data[position:position+sigcrypto.SignatureSize])
		position += sigcrypto.SignatureSize
	}
	var setHash sigcrypto.Hash
	copy(setHash[:], data[position:])
	return commitments, setHash, nil
}

func EncodeReveal(reveal Reveal) []byte {
	output := make([]byte, 1+len(reveal.Blinding))
	output[0] = reveal.Vote
	copy(output[1:], reveal.Blinding[:])
	return output
}

func DecodeReveal(data []byte) (Reveal, error) {
	if len(data) != 33 {
		return Reveal{}, errors.New("omen: invalid reveal payload")
	}
	result := Reveal{Vote: data[0]}
	copy(result.Blinding[:], data[1:])
	return result, nil
}

func EncodeRevealSet(reveals []Reveal) ([]byte, error) {
	if len(reveals) < 2 || len(reveals) > 255 {
		return nil, errors.New("omen: reveal count must be 2..255")
	}
	output := make([]byte, 1, 1+len(reveals)*33)
	output[0] = byte(len(reveals))
	for _, reveal := range reveals {
		output = append(output, reveal.Vote)
		output = append(output, reveal.Blinding[:]...)
	}
	return output, nil
}

func DecodeRevealSet(data []byte) ([]Reveal, error) {
	if len(data) < 1 || len(data) > frame.MaxPayloadLen {
		return nil, errors.New("omen: invalid reveal-set payload length")
	}
	count := int(data[0])
	if count < 2 || len(data) != 1+count*33 {
		return nil, errors.New("omen: invalid reveal-set length")
	}
	position := 1
	reveals := make([]Reveal, count)
	for index := range reveals {
		reveals[index].Vote = data[position]
		position++
		copy(reveals[index].Blinding[:], data[position:position+32])
		position += 32
	}
	return reveals, nil
}

func commitSetHash(commitments []Commitment) sigcrypto.Hash {
	converted := make([]sigcrypto.OmenCommitment, len(commitments))
	for index, commitment := range commitments {
		converted[index] = sigcrypto.OmenCommitment{
			Slot: commitment.Slot, Commitment: commitment.Commitment, Signature: commitment.Signature,
		}
	}
	return sigcrypto.OmenCommitSetHash(converted)
}

func equalPeerLists(first, second []Peer) bool {
	if len(first) != len(second) {
		return false
	}
	for index := range first {
		if first[index].Slot != second[index].Slot || first[index].Nick != second[index].Nick ||
			!bytes.Equal(first[index].PublicKey[:], second[index].PublicKey[:]) {
			return false
		}
	}
	return true
}
