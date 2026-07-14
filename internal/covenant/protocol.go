package covenant

import (
	"bytes"
	"errors"
	"fmt"
	"unicode/utf8"

	"github.com/no-way-labs/cauldron/internal/frame"
	"github.com/no-way-labs/cauldron/internal/sigcrypto"
)

const Magic = "COVENANT_HELLO"

const (
	MessageJoin      byte = 1
	MessageLeave     byte = 3
	MessagePublicKey byte = 10
	MessageRoster    byte = 11
	MessagePhase     byte = 12
	MessageSignature byte = 13
	MessageCovenant  byte = 14
	MessageAbort     byte = 19
)

const (
	PhaseLobby byte = iota
	PhaseSeal
	PhaseDone
)

func ValidMessageType(value byte) bool {
	switch value {
	case MessageJoin, MessageLeave, MessagePublicKey, MessageRoster,
		MessagePhase, MessageSignature, MessageCovenant, MessageAbort:
		return true
	default:
		return false
	}
}

type Member struct {
	Nick      string
	PublicKey sigcrypto.PublicKey
}

func EncodeRoster(members []Member) ([]byte, error) {
	if len(members) < MinMembers || len(members) > MaxMembers {
		return nil, fmt.Errorf("covenant: roster count must be %d..%d", MinMembers, MaxMembers)
	}
	length := 1
	for index, member := range members {
		if err := validateNick(member.Nick); err != nil {
			return nil, fmt.Errorf("covenant: member %d: %w", index, err)
		}
		if index > 0 && bytes.Compare(members[index-1].PublicKey[:], member.PublicKey[:]) >= 0 {
			return nil, errors.New("covenant: roster is not strictly sorted by public key")
		}
		length += 1 + len(member.Nick) + sigcrypto.PublicKeySize
	}
	if length > frame.MaxPayloadLen {
		return nil, frame.ErrPayload
	}
	output := make([]byte, 1, length)
	output[0] = byte(len(members))
	for _, member := range members {
		output = append(output, byte(len(member.Nick)))
		output = append(output, member.Nick...)
		output = append(output, member.PublicKey[:]...)
	}
	return output, nil
}

func DecodeRoster(data []byte) ([]Member, error) {
	if len(data) < 1 {
		return nil, errors.New("covenant: empty roster payload")
	}
	count := int(data[0])
	if count < MinMembers {
		return nil, fmt.Errorf("covenant: roster count must be at least %d", MinMembers)
	}
	position := 1
	members := make([]Member, count)
	for index := 0; index < count; index++ {
		if position >= len(data) {
			return nil, errors.New("covenant: truncated roster nick length")
		}
		nickLength := int(data[position])
		position++
		if nickLength == 0 || nickLength > frame.MaxSenderLen || position+nickLength+sigcrypto.PublicKeySize > len(data) {
			return nil, errors.New("covenant: invalid roster member length")
		}
		nickBytes := data[position : position+nickLength]
		if !utf8.Valid(nickBytes) {
			return nil, errors.New("covenant: roster nick is invalid UTF-8")
		}
		position += nickLength
		members[index].Nick = string(nickBytes)
		copy(members[index].PublicKey[:], data[position:position+sigcrypto.PublicKeySize])
		position += sigcrypto.PublicKeySize
		if index > 0 && bytes.Compare(members[index-1].PublicKey[:], members[index].PublicKey[:]) >= 0 {
			return nil, errors.New("covenant: roster keys are duplicate or unsorted")
		}
	}
	if position != len(data) {
		return nil, errors.New("covenant: trailing roster bytes")
	}
	return members, nil
}

func EncodePhase(phase byte) ([]byte, error) {
	if phase > PhaseDone {
		return nil, errors.New("covenant: invalid phase")
	}
	return []byte{phase}, nil
}

func DecodePhase(data []byte) (byte, error) {
	if len(data) != 1 || data[0] > PhaseDone {
		return 0, errors.New("covenant: invalid phase payload")
	}
	return data[0], nil
}
