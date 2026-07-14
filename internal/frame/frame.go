// Package frame implements the shared seance/omen/covenant wire envelope.
package frame

import (
	"encoding/binary"
	"errors"
	"fmt"
	"io"
	"unicode/utf8"

	"github.com/no-way-labs/cauldron/internal/secretbox"
)

const (
	MaxSenderLen  = 32
	MaxPayloadLen = 65536
	HeaderLen     = 1 + 8 + 1 + 4 + secretbox.NonceSize + secretbox.TagSize
)

var (
	ErrInvalidType = errors.New("frame: invalid message type")
	ErrSender      = errors.New("frame: invalid sender")
	ErrPayload     = errors.New("frame: payload too large")
)

type Frame struct {
	Type       byte
	Timestamp  uint64
	Sender     string
	Nonce      [secretbox.NonceSize]byte
	Tag        [secretbox.TagSize]byte
	Ciphertext []byte
}

// TypeValidator lets each app reject bytes outside its own message enum.
type TypeValidator func(byte) bool

func Write(w io.Writer, value Frame, valid TypeValidator) error {
	if valid != nil && !valid(value.Type) {
		return ErrInvalidType
	}
	if len(value.Sender) > MaxSenderLen || !utf8.ValidString(value.Sender) {
		return ErrSender
	}
	if len(value.Ciphertext) > MaxPayloadLen {
		return ErrPayload
	}
	var fixed [1 + 8 + 1]byte
	fixed[0] = value.Type
	binary.BigEndian.PutUint64(fixed[1:9], value.Timestamp)
	fixed[9] = byte(len(value.Sender))
	if err := writeAll(w, fixed[:]); err != nil {
		return fmt.Errorf("frame: write header: %w", err)
	}
	if err := writeAll(w, []byte(value.Sender)); err != nil {
		return fmt.Errorf("frame: write sender: %w", err)
	}
	var payloadLen [4]byte
	binary.BigEndian.PutUint32(payloadLen[:], uint32(len(value.Ciphertext)))
	parts := []struct {
		label string
		data  []byte
	}{
		{"payload length", payloadLen[:]},
		{"nonce", value.Nonce[:]},
		{"tag", value.Tag[:]},
		{"ciphertext", value.Ciphertext},
	}
	for _, part := range parts {
		if err := writeAll(w, part.data); err != nil {
			return fmt.Errorf("frame: write %s: %w", part.label, err)
		}
	}
	return nil
}

func Read(r io.Reader, valid TypeValidator) (Frame, error) {
	var fixed [1 + 8 + 1]byte
	if _, err := io.ReadFull(r, fixed[:]); err != nil {
		return Frame{}, fmt.Errorf("frame: read header: %w", err)
	}
	if valid != nil && !valid(fixed[0]) {
		return Frame{}, ErrInvalidType
	}
	value := Frame{Type: fixed[0], Timestamp: binary.BigEndian.Uint64(fixed[1:9])}
	senderLen := int(fixed[9])
	if senderLen > MaxSenderLen {
		return Frame{}, ErrSender
	}
	sender := make([]byte, senderLen)
	if _, err := io.ReadFull(r, sender); err != nil {
		return Frame{}, fmt.Errorf("frame: read sender: %w", err)
	}
	if !utf8.Valid(sender) {
		return Frame{}, ErrSender
	}
	value.Sender = string(sender)

	var payloadLenBytes [4]byte
	if _, err := io.ReadFull(r, payloadLenBytes[:]); err != nil {
		return Frame{}, fmt.Errorf("frame: read payload length: %w", err)
	}
	payloadLen := binary.BigEndian.Uint32(payloadLenBytes[:])
	if payloadLen > MaxPayloadLen {
		return Frame{}, ErrPayload
	}
	if _, err := io.ReadFull(r, value.Nonce[:]); err != nil {
		return Frame{}, fmt.Errorf("frame: read nonce: %w", err)
	}
	if _, err := io.ReadFull(r, value.Tag[:]); err != nil {
		return Frame{}, fmt.Errorf("frame: read tag: %w", err)
	}
	value.Ciphertext = make([]byte, int(payloadLen))
	if _, err := io.ReadFull(r, value.Ciphertext); err != nil {
		return Frame{}, fmt.Errorf("frame: read ciphertext: %w", err)
	}
	return value, nil
}

func writeAll(w io.Writer, data []byte) error {
	for len(data) > 0 {
		n, err := w.Write(data)
		if err != nil {
			return err
		}
		if n <= 0 {
			return io.ErrShortWrite
		}
		data = data[n:]
	}
	return nil
}
