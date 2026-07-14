package jsonstrict

import (
	"encoding/json"
	"errors"
	"fmt"
)

type TopLevelMember struct {
	Key       string
	KeyOffset int // byte offset of the opening quote for this member's key
}

// TopLevelMembers returns the exact physical offsets of an object's top-level
// keys. Validate is called first, so escaped strings and nested values can be
// scanned without accepting malformed JSON.
func TopLevelMembers(data []byte) ([]TopLevelMember, error) {
	if err := Validate(data); err != nil {
		return nil, err
	}
	position := skipSpace(data, 0)
	if position >= len(data) || data[position] != '{' {
		return nil, errors.New("jsonstrict: root is not an object")
	}
	position++
	var members []TopLevelMember
	for {
		position = skipSpace(data, position)
		if position >= len(data) {
			return nil, errors.New("jsonstrict: unterminated object")
		}
		if data[position] == '}' {
			return members, nil
		}
		if data[position] != '"' {
			return nil, errors.New("jsonstrict: expected object key")
		}
		start := position
		end, err := scanString(data, position)
		if err != nil {
			return nil, err
		}
		var key string
		if err := json.Unmarshal(data[start:end], &key); err != nil {
			return nil, fmt.Errorf("jsonstrict: decode key: %w", err)
		}
		members = append(members, TopLevelMember{Key: key, KeyOffset: start})
		position = skipSpace(data, end)
		if position >= len(data) || data[position] != ':' {
			return nil, errors.New("jsonstrict: expected colon")
		}
		position, err = scanValue(data, position+1)
		if err != nil {
			return nil, err
		}
		position = skipSpace(data, position)
		if position >= len(data) {
			return nil, errors.New("jsonstrict: unterminated object")
		}
		switch data[position] {
		case ',':
			position++
		case '}':
			return members, nil
		default:
			return nil, errors.New("jsonstrict: expected comma or object end")
		}
	}
}

func scanValue(data []byte, position int) (int, error) {
	position = skipSpace(data, position)
	if position >= len(data) {
		return 0, errors.New("jsonstrict: missing value")
	}
	if data[position] == '"' {
		return scanString(data, position)
	}
	if data[position] == '{' || data[position] == '[' {
		stack := []byte{data[position]}
		position++
		for position < len(data) && len(stack) > 0 {
			switch data[position] {
			case '"':
				end, err := scanString(data, position)
				if err != nil {
					return 0, err
				}
				position = end
				continue
			case '{', '[':
				stack = append(stack, data[position])
			case '}':
				if stack[len(stack)-1] != '{' {
					return 0, errors.New("jsonstrict: mismatched object end")
				}
				stack = stack[:len(stack)-1]
			case ']':
				if stack[len(stack)-1] != '[' {
					return 0, errors.New("jsonstrict: mismatched array end")
				}
				stack = stack[:len(stack)-1]
			}
			position++
		}
		if len(stack) != 0 {
			return 0, errors.New("jsonstrict: unterminated structured value")
		}
		return position, nil
	}
	for position < len(data) {
		switch data[position] {
		case ',', '}', ']', ' ', '\t', '\r', '\n':
			return position, nil
		default:
			position++
		}
	}
	return position, nil
}

func scanString(data []byte, position int) (int, error) {
	if position >= len(data) || data[position] != '"' {
		return 0, errors.New("jsonstrict: expected string")
	}
	position++
	for position < len(data) {
		switch data[position] {
		case '\\':
			position += 2
			continue
		case '"':
			return position + 1, nil
		default:
			position++
		}
	}
	return 0, errors.New("jsonstrict: unterminated string")
}

func skipSpace(data []byte, position int) int {
	for position < len(data) {
		switch data[position] {
		case ' ', '\t', '\r', '\n':
			position++
		default:
			return position
		}
	}
	return position
}
