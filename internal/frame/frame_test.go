package frame

import (
	"bytes"
	"errors"
	"testing"
)

func TestRoundTripAndLayout(t *testing.T) {
	value := Frame{Type: 2, Timestamp: 0x0102030405060708, Sender: "nick", Ciphertext: []byte("hello")}
	for i := range value.Nonce {
		value.Nonce[i] = byte(i)
	}
	for i := range value.Tag {
		value.Tag[i] = byte(0xa0 + i)
	}
	valid := func(value byte) bool { return value >= 1 && value <= 5 }
	var wire bytes.Buffer
	if err := Write(&wire, value, valid); err != nil {
		t.Fatal(err)
	}
	if got := wire.Bytes()[0]; got != 2 {
		t.Fatalf("type byte = %d", got)
	}
	if got := wire.Bytes()[9]; got != 4 {
		t.Fatalf("sender length = %d", got)
	}
	decoded, err := Read(&wire, valid)
	if err != nil {
		t.Fatal(err)
	}
	if decoded.Type != value.Type || decoded.Timestamp != value.Timestamp || decoded.Sender != value.Sender ||
		!bytes.Equal(decoded.Nonce[:], value.Nonce[:]) || !bytes.Equal(decoded.Tag[:], value.Tag[:]) ||
		!bytes.Equal(decoded.Ciphertext, value.Ciphertext) {
		t.Fatalf("round trip mismatch: %#v", decoded)
	}
}

func TestLimitsAndUnknownTypes(t *testing.T) {
	valid := func(value byte) bool { return value == 1 }
	if err := Write(&bytes.Buffer{}, Frame{Type: 2}, valid); !errors.Is(err, ErrInvalidType) {
		t.Fatalf("unknown type error = %v", err)
	}
	if err := Write(&bytes.Buffer{}, Frame{Type: 1, Sender: string(bytes.Repeat([]byte{'x'}, MaxSenderLen+1))}, valid); !errors.Is(err, ErrSender) {
		t.Fatalf("sender error = %v", err)
	}
	if err := Write(&bytes.Buffer{}, Frame{Type: 1, Ciphertext: make([]byte, MaxPayloadLen+1)}, valid); !errors.Is(err, ErrPayload) {
		t.Fatalf("payload error = %v", err)
	}
}

func FuzzRead(f *testing.F) {
	f.Add([]byte{})
	f.Add([]byte{1})
	f.Add(bytes.Repeat([]byte{0}, HeaderLen))
	f.Fuzz(func(t *testing.T, data []byte) {
		_, _ = Read(bytes.NewReader(data), func(value byte) bool { return value >= 1 && value <= 20 })
	})
}
