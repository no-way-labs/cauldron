package cli

import (
	"errors"
	"reflect"
	"testing"
)

func TestParseOptionsAfterPositionals(t *testing.T) {
	var password string
	var quiet bool
	var positionals []string
	err := Parse([]string{"host:1", "payload", "--password", "secret", "--quiet"}, map[string]Option{
		"--password": {TakesValue: true, Apply: func(value string) error { password = value; return nil }},
		"--quiet":    {Apply: func(string) error { quiet = true; return nil }},
	}, func(value string) error { positionals = append(positionals, value); return nil })
	if err != nil {
		t.Fatal(err)
	}
	if password != "secret" || !quiet || !reflect.DeepEqual(positionals, []string{"host:1", "payload"}) {
		t.Fatalf("password=%q quiet=%v positionals=%v", password, quiet, positionals)
	}
}

func TestParseRejectsUnknownMissingAndEmpty(t *testing.T) {
	options := map[string]Option{"--password": {TakesValue: true}}
	for _, args := range [][]string{{"--unknown"}, {"--password"}, {"--password", ""}} {
		if err := Parse(args, options, nil); !errors.Is(err, ErrUsage) {
			t.Fatalf("Parse(%q) error = %v", args, err)
		}
	}
}

func TestTargetSplitQuirks(t *testing.T) {
	host, port, err := SplitTargetFirst("name:123")
	if err != nil || host != "name" || port != 123 {
		t.Fatalf("first split: %q %d %v", host, port, err)
	}
	host, port, err = SplitTargetLast("name:with:colons:456")
	if err != nil || host != "name:with:colons" || port != 456 {
		t.Fatalf("last split: %q %d %v", host, port, err)
	}
}
