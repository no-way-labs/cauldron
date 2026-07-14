package ident

import (
	"bytes"
	"regexp"
	"testing"
)

type zeroReader struct{}

func (zeroReader) Read(p []byte) (int, error) {
	clear(p)
	return len(p), nil
}

func TestWordlistAndUnpaddedNumber(t *testing.T) {
	if WordCount() != 787 {
		t.Fatalf("word count = %d", WordCount())
	}
	generated, err := GenerateFrom(zeroReader{})
	if err != nil {
		t.Fatal(err)
	}
	want := []byte(words[0] + "-" + words[0] + "-" + words[0] + "-0")
	if !bytes.Equal(generated, want) {
		t.Fatalf("generated %q, want %q", generated, want)
	}
	if bytes.HasSuffix(generated, []byte("-00")) {
		t.Fatal("number was zero-padded")
	}
}

func TestGeneratedShape(t *testing.T) {
	generated, err := Generate()
	if err != nil {
		t.Fatal(err)
	}
	if !regexp.MustCompile(`^[a-z]+-[a-z]+-[a-z]+-[0-9]{1,2}$`).Match(generated) {
		t.Fatalf("unexpected identifier: %q", generated)
	}
}
