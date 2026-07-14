package seance

import (
	"fmt"
	"io"
	"sync"
	"time"

	"github.com/no-way-labs/cauldron/internal/frame"
	"github.com/no-way-labs/cauldron/internal/secretbox"
)

func encryptedFrame(key *secretbox.Key, messageType byte, sender string, payload []byte, now time.Time) (frame.Frame, error) {
	if len(payload) > frame.MaxPayloadLen {
		return frame.Frame{}, frame.ErrPayload
	}
	box, err := secretbox.Seal(key, payload)
	if err != nil {
		return frame.Frame{}, err
	}
	return frame.Frame{
		Type: messageType, Timestamp: uint64(now.Unix()), Sender: sender,
		Nonce: box.Nonce, Tag: box.Tag, Ciphertext: box.Ciphertext,
	}, nil
}

func writeFrame(writer io.Writer, writeMu *sync.Mutex, value frame.Frame) error {
	if writeMu != nil {
		writeMu.Lock()
		defer writeMu.Unlock()
	}
	if err := frame.Write(writer, value, ValidMessageType); err != nil {
		return fmt.Errorf("seance: send frame: %w", err)
	}
	return nil
}

func sendEncrypted(writer io.Writer, writeMu *sync.Mutex, key *secretbox.Key, messageType byte, sender string, payload []byte, now time.Time) error {
	value, err := encryptedFrame(key, messageType, sender, payload, now)
	if err != nil {
		return err
	}
	defer secretbox.Zero(value.Ciphertext)
	return writeFrame(writer, writeMu, value)
}

func readEncrypted(reader io.Reader, key *secretbox.Key) (frame.Frame, []byte, error) {
	value, err := frame.Read(reader, ValidMessageType)
	if err != nil {
		return frame.Frame{}, nil, err
	}
	plaintext, err := secretbox.Open(key, secretbox.Box{
		Nonce: value.Nonce, Tag: value.Tag, Ciphertext: value.Ciphertext,
	})
	if err != nil {
		secretbox.Zero(value.Ciphertext)
		return value, nil, fmt.Errorf("seance: decrypt frame: %w", err)
	}
	return value, plaintext, nil
}
