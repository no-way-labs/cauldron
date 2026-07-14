//lint:file-ignore ST1005 Legacy error capitalization is part of mitt's CLI compatibility surface.
package mitt

import (
	"bytes"
	"context"
	"encoding/binary"
	"errors"
	"fmt"
	"io"
	"net"
	"os"
	"path/filepath"
	"time"

	"github.com/no-way-labs/cauldron/internal/secretbox"
)

const MaxPayloadBytes = uint64(1 << 30)

var ErrTimeout = errors.New("mitt: transfer timed out")

type payloadKind uint8

const (
	payloadFile payloadKind = iota
	payloadStdin
	payloadText
)

// Payload describes one file, stdin stream, or literal text transfer.
type Payload struct {
	kind   payloadKind
	path   string
	reader io.Reader
	text   string
}

func FilePayload(path string) Payload       { return Payload{kind: payloadFile, path: path} }
func StdinPayload(reader io.Reader) Payload { return Payload{kind: payloadStdin, reader: reader} }
func TextPayload(text string) Payload       { return Payload{kind: payloadText, text: text} }

type payloadData struct {
	filename string
	data     []byte
}

// Send performs the single-request mitt transfer and waits for its one-byte ack.
func Send(ctx context.Context, address string, payload Payload, key *secretbox.Key, timeout time.Duration) error {
	if timeout < 0 {
		return errors.New("mitt: timeout cannot be negative")
	}
	loaded, err := loadPayload(payload)
	if err != nil {
		return err
	}
	defer secretbox.Zero(loaded.data)
	if len(loaded.filename) == 0 || len(loaded.filename) > 65535 {
		return errors.New("Filename too long")
	}
	box, err := secretbox.Seal(key, loaded.data)
	if err != nil {
		return fmt.Errorf("encrypt payload: %w", err)
	}
	defer secretbox.Zero(box.Ciphertext)

	dialer := net.Dialer{Timeout: timeout}
	connection, err := dialer.DialContext(ctx, "tcp", address)
	if err != nil {
		if isTimeout(err) {
			return ErrTimeout
		}
		return fmt.Errorf("Connection failed to %s: %w", address, err)
	}
	defer connection.Close()
	if timeout > 0 {
		if err := connection.SetDeadline(time.Now().Add(timeout)); err != nil {
			return fmt.Errorf("set transfer timeout: %w", err)
		}
	}

	var header [2]byte
	binary.BigEndian.PutUint16(header[:], uint16(len(loaded.filename)))
	if err := writeParts(connection,
		header[:], []byte(loaded.filename), uint64Bytes(uint64(len(box.Ciphertext))),
		box.Nonce[:], box.Tag[:], box.Ciphertext,
	); err != nil {
		if isTimeout(err) {
			return ErrTimeout
		}
		return fmt.Errorf("send payload: %w", err)
	}
	var ack [1]byte
	if _, err := io.ReadFull(connection, ack[:]); err != nil {
		if isTimeout(err) {
			return ErrTimeout
		}
		return errors.New("No acknowledgment from server")
	}
	if ack[0] != 0 {
		return errors.New("Server rejected transfer")
	}
	return nil
}

func loadPayload(payload Payload) (payloadData, error) {
	switch payload.kind {
	case payloadFile:
		file, err := os.Open(payload.path)
		if err != nil {
			return payloadData{}, fmt.Errorf("Failed to read file: %w", err)
		}
		defer file.Close()
		data, err := readPayload(file)
		if err != nil {
			return payloadData{}, fmt.Errorf("Failed to read file: %w", err)
		}
		return payloadData{filename: filepath.Base(payload.path), data: data}, nil
	case payloadStdin:
		if payload.reader == nil {
			return payloadData{}, errors.New("Failed to read stdin: nil reader")
		}
		data, err := readPayload(payload.reader)
		if err != nil {
			return payloadData{}, fmt.Errorf("Failed to read stdin: %w", err)
		}
		return payloadData{filename: "stdin", data: data}, nil
	case payloadText:
		if uint64(len(payload.text)) > MaxPayloadBytes {
			return payloadData{}, fmt.Errorf("text exceeds %d bytes", MaxPayloadBytes)
		}
		return payloadData{filename: "text.txt", data: []byte(payload.text)}, nil
	default:
		return payloadData{}, errors.New("mitt: invalid payload kind")
	}
}

func readPayload(reader io.Reader) ([]byte, error) {
	data, err := io.ReadAll(io.LimitReader(reader, int64(MaxPayloadBytes)+1))
	if err != nil {
		return nil, err
	}
	if uint64(len(data)) > MaxPayloadBytes {
		secretbox.Zero(data)
		return nil, fmt.Errorf("payload exceeds %d bytes", MaxPayloadBytes)
	}
	return data, nil
}

func uint64Bytes(value uint64) []byte {
	var encoded [8]byte
	binary.BigEndian.PutUint64(encoded[:], value)
	return encoded[:]
}

func writeParts(writer io.Writer, parts ...[]byte) error {
	for _, part := range parts {
		if _, err := io.Copy(writer, bytes.NewReader(part)); err != nil {
			return err
		}
	}
	return nil
}

func isTimeout(err error) bool {
	var networkError net.Error
	return errors.As(err, &networkError) && networkError.Timeout()
}
