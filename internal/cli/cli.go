// Package cli contains the small argv parser shared by Cauldron's command
// shims. It keeps parsing after positional arguments, unlike flag.FlagSet.
package cli

import (
	"errors"
	"fmt"
	"os"
	"strconv"
	"strings"
)

var ErrUsage = errors.New("cli: usage")

type Option struct {
	TakesValue bool
	AllowEmpty bool
	Apply      func(string) error
}

// Parse accepts registered options in any argv position. A bare "-" is a
// positional (mitt stdin); any other unregistered dash-prefixed token fails.
func Parse(args []string, options map[string]Option, positional func(string) error) error {
	for i := 0; i < len(args); i++ {
		arg := args[i]
		option, known := options[arg]
		if known {
			value := ""
			if option.TakesValue {
				if i+1 >= len(args) {
					return fmt.Errorf("%w: %s requires a value", ErrUsage, arg)
				}
				i++
				value = args[i]
				if value == "" && !option.AllowEmpty {
					return fmt.Errorf("%w: %s requires a non-empty value", ErrUsage, arg)
				}
			}
			if option.Apply != nil {
				if err := option.Apply(value); err != nil {
					return fmt.Errorf("%w: %s: %v", ErrUsage, arg, err)
				}
			}
			continue
		}
		if arg != "-" && strings.HasPrefix(arg, "-") {
			return fmt.Errorf("%w: unknown option %s", ErrUsage, arg)
		}
		if positional == nil {
			return fmt.Errorf("%w: unexpected argument %s", ErrUsage, arg)
		}
		if err := positional(arg); err != nil {
			return fmt.Errorf("%w: %v", ErrUsage, err)
		}
	}
	return nil
}

// ResolveSecret copies an explicit flag or non-empty environment value into an
// owned buffer. Explicit empty values fail closed; exported-but-empty env vars
// are treated as unset.
func ResolveSecret(flagSet bool, flagValue, envName string) ([]byte, bool, error) {
	if flagSet {
		if flagValue == "" {
			return nil, false, fmt.Errorf("%w: explicit %s value is empty", ErrUsage, envName)
		}
		return []byte(flagValue), true, nil
	}
	value, ok := os.LookupEnv(envName)
	if !ok || value == "" {
		return nil, false, nil
	}
	return []byte(value), true, nil
}

func SplitTargetFirst(target string) (string, uint16, error) {
	return splitTarget(target, strings.IndexByte(target, ':'))
}

func SplitTargetLast(target string) (string, uint16, error) {
	return splitTarget(target, strings.LastIndexByte(target, ':'))
}

func splitTarget(target string, colon int) (string, uint16, error) {
	if colon <= 0 || colon == len(target)-1 {
		return "", 0, errors.New("target must be host:port")
	}
	host := target[:colon]
	parsed, err := strconv.ParseUint(target[colon+1:], 10, 16)
	if err != nil || parsed == 0 {
		return "", 0, errors.New("port must be between 1 and 65535")
	}
	return host, uint16(parsed), nil
}

func Uint16(value string) (uint16, error) {
	parsed, err := strconv.ParseUint(value, 10, 16)
	if err != nil {
		return 0, errors.New("must be a number between 0 and 65535")
	}
	return uint16(parsed), nil
}

func PositiveUint16(value string) (uint16, error) {
	parsed, err := Uint16(value)
	if err != nil || parsed == 0 {
		return 0, errors.New("must be a number between 1 and 65535")
	}
	return parsed, nil
}

func Uint64(value string) (uint64, error) {
	parsed, err := strconv.ParseUint(value, 10, 64)
	if err != nil {
		return 0, errors.New("must be a non-negative integer")
	}
	return parsed, nil
}
