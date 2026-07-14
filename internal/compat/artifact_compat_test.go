package compat_test

import (
	"bytes"
	"os"
	"path/filepath"
	"testing"

	"github.com/no-way-labs/cauldron/internal/covenant"
	"github.com/no-way-labs/cauldron/internal/omen"
)

func TestCapturedMixedCovenantArtifacts(t *testing.T) {
	for _, name := range []string{"covenant-zig-host.json", "covenant-go-host.json"} {
		t.Run(name, func(t *testing.T) {
			data := readInteropFixture(t, name)
			result, err := covenant.VerifyArtifact(data)
			if err != nil || !result.Valid || result.MemberCount != 2 {
				t.Fatalf("captured mixed covenant rejected: valid=%v err=%v", result.Valid, err)
			}

			tampered := append([]byte(nil), data...)
			marker := []byte(`"nick":"`)
			position := bytes.Index(tampered, marker)
			if position < 0 || position+len(marker) >= len(tampered) {
				t.Fatal("fixture has no member nick")
			}
			tampered[position+len(marker)] ^= 1
			changed, changedErr := covenant.VerifyArtifact(tampered)
			if changedErr == nil && changed.Valid {
				t.Fatal("renamed member remained valid")
			}
		})
	}
}

func TestCapturedMixedOmenArtifacts(t *testing.T) {
	for _, name := range []string{"omen-zig-host.json", "omen-go-host.json"} {
		t.Run(name, func(t *testing.T) {
			data := readInteropFixture(t, name)
			result, err := omen.VerifyArtifact(data)
			if err != nil || !result.Valid || result.VoterCount != 2 {
				t.Fatalf("captured mixed omen rejected: valid=%v err=%v", result.Valid, err)
			}
			if len(result.RevealSlots) != result.VoterCount {
				t.Fatalf("reveal-slot linkage = %#v", result.RevealSlots)
			}

			tampered := append([]byte(nil), data...)
			marker := []byte(`"host_signature":"`)
			position := bytes.LastIndex(tampered, marker)
			if position < 0 || position+len(marker) >= len(tampered) {
				t.Fatal("fixture has no host signature")
			}
			index := position + len(marker)
			if tampered[index] == '0' {
				tampered[index] = '1'
			} else {
				tampered[index] = '0'
			}
			changed, changedErr := omen.VerifyArtifact(tampered)
			if changedErr == nil && changed.Valid {
				t.Fatal("modified host signature remained valid")
			}
		})
	}
}

func readInteropFixture(t *testing.T, name string) []byte {
	t.Helper()
	path := filepath.Join("..", "..", "testdata", "interop", name)
	data, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	return data
}
