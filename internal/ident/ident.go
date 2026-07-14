// Package ident generates Cauldron's human-readable room passwords and nicks.
package ident

import (
	"crypto/rand"
	_ "embed"
	"fmt"
	"io"
	"math/big"
	"strconv"
	"strings"
)

//go:embed wordlist.txt
var wordlistData string

var words = loadWords()

func loadWords() []string {
	clean := strings.TrimSuffix(wordlistData, "\n")
	if strings.ContainsRune(clean, '\r') {
		panic("ident: wordlist contains CR bytes")
	}
	loaded := strings.Split(clean, "\n")
	if len(loaded) != 787 {
		panic(fmt.Sprintf("ident: wordlist has %d entries, want 787", len(loaded)))
	}
	for _, word := range loaded {
		if word == "" {
			panic("ident: wordlist contains an empty entry")
		}
	}
	return loaded
}

// Generate returns word-word-word-N using the exact embedded 787-word list.
// N is in [0,99] and deliberately is not zero-padded.
func Generate() ([]byte, error) {
	return GenerateFrom(rand.Reader)
}

// GenerateFrom injects randomness for deterministic tests.
func GenerateFrom(random io.Reader) ([]byte, error) {
	if random == nil {
		return nil, fmt.Errorf("ident: nil randomness source")
	}
	indexes := [3]int{}
	for i := range indexes {
		value, err := rand.Int(random, big.NewInt(int64(len(words))))
		if err != nil {
			return nil, fmt.Errorf("ident: choose word %d: %w", i+1, err)
		}
		indexes[i] = int(value.Int64())
	}
	number, err := rand.Int(random, big.NewInt(100))
	if err != nil {
		return nil, fmt.Errorf("ident: choose number: %w", err)
	}
	result := make([]byte, 0, len(words[indexes[0]])+len(words[indexes[1]])+len(words[indexes[2]])+6)
	result = append(result, words[indexes[0]]...)
	result = append(result, '-')
	result = append(result, words[indexes[1]]...)
	result = append(result, '-')
	result = append(result, words[indexes[2]]...)
	result = append(result, '-')
	result = strconv.AppendInt(result, number.Int64(), 10)
	return result, nil
}

func WordCount() int { return len(words) }
