// Package jsonstrict adds duplicate-key, UTF-8, and trailing-value checks to
// encoding/json. Artifact verifiers use it before decoding into exact fields.
package jsonstrict

import (
	"bytes"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"unicode/utf8"
)

func Validate(data []byte) error {
	if !utf8.Valid(data) {
		return errors.New("jsonstrict: invalid UTF-8")
	}
	decoder := json.NewDecoder(bytes.NewReader(data))
	decoder.UseNumber()
	if err := value(decoder); err != nil {
		return err
	}
	if token, err := decoder.Token(); err != io.EOF {
		if err != nil {
			return fmt.Errorf("jsonstrict: trailing JSON: %w", err)
		}
		return fmt.Errorf("jsonstrict: trailing JSON value %v", token)
	}
	return nil
}

func value(decoder *json.Decoder) error {
	token, err := decoder.Token()
	if err != nil {
		return fmt.Errorf("jsonstrict: %w", err)
	}
	delimiter, structured := token.(json.Delim)
	if !structured {
		return nil
	}
	switch delimiter {
	case '{':
		seen := make(map[string]struct{})
		for decoder.More() {
			keyToken, err := decoder.Token()
			if err != nil {
				return fmt.Errorf("jsonstrict: object key: %w", err)
			}
			key, ok := keyToken.(string)
			if !ok {
				return errors.New("jsonstrict: object key is not a string")
			}
			if _, duplicate := seen[key]; duplicate {
				return fmt.Errorf("jsonstrict: duplicate object key %q", key)
			}
			seen[key] = struct{}{}
			if err := value(decoder); err != nil {
				return err
			}
		}
		closing, err := decoder.Token()
		if err != nil {
			return fmt.Errorf("jsonstrict: close object: %w", err)
		}
		if closing != json.Delim('}') {
			return errors.New("jsonstrict: object did not close")
		}
		return nil
	case '[':
		for decoder.More() {
			if err := value(decoder); err != nil {
				return err
			}
		}
		closing, err := decoder.Token()
		if err != nil {
			return fmt.Errorf("jsonstrict: close array: %w", err)
		}
		if closing != json.Delim(']') {
			return errors.New("jsonstrict: array did not close")
		}
		return nil
	default:
		return fmt.Errorf("jsonstrict: unexpected delimiter %q", delimiter)
	}
}
