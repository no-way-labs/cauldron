package covenant

import (
	"fmt"
	"io"
	"sync"
	"time"

	"github.com/no-way-labs/cauldron/internal/frame"
	"github.com/no-way-labs/cauldron/internal/secretbox"
)

func sendEncrypted(writer io.Writer, writeMu *sync.Mutex, key *secretbox.Key, messageType byte, sender string, payload []byte, now time.Time) error {
	if len(payload) > frame.MaxPayloadLen {
		return frame.ErrPayload
	}
	box, err := secretbox.Seal(key, payload)
	if err != nil {
		return err
	}
	defer secretbox.Zero(box.Ciphertext)
	value := frame.Frame{
		Type: messageType, Timestamp: uint64(now.Unix()), Sender: sender,
		Nonce: box.Nonce, Tag: box.Tag, Ciphertext: box.Ciphertext,
	}
	if writeMu != nil {
		writeMu.Lock()
		defer writeMu.Unlock()
	}
	if err := frame.Write(writer, value, ValidMessageType); err != nil {
		return fmt.Errorf("covenant: send frame: %w", err)
	}
	return nil
}

func readEncrypted(reader io.Reader, key *secretbox.Key) (frame.Frame, []byte, error) {
	value, err := frame.Read(reader, ValidMessageType)
	if err != nil {
		return frame.Frame{}, nil, err
	}
	plaintext, err := secretbox.Open(key, secretbox.Box{
		Nonce: value.Nonce, Tag: value.Tag, Ciphertext: value.Ciphertext,
	})
	secretbox.Zero(value.Ciphertext)
	if err != nil {
		return value, nil, fmt.Errorf("covenant: decrypt frame: %w", err)
	}
	return value, plaintext, nil
}
