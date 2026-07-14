package jsonstrict

import (
	"strings"
	"testing"
)

func TestValidate(t *testing.T) {
	for _, valid := range []string{`null`, `{"a":[1,{"b":true}]}`, `{"a":1,"A":2}`} {
		if err := Validate([]byte(valid)); err != nil {
			t.Errorf("Validate(%s): %v", valid, err)
		}
	}
	for _, invalid := range []string{
		`{"a":1,"a":2}`,
		`{"a":{"b":1,"b":2}}`,
		`[] {}`,
		``,
	} {
		if err := Validate([]byte(invalid)); err == nil {
			t.Errorf("Validate(%s) succeeded", invalid)
		}
	}
}

func TestEscapedDuplicateKey(t *testing.T) {
	err := Validate([]byte(`{"a":1,"\u0061":2}`))
	if err == nil || !strings.Contains(err.Error(), "duplicate") {
		t.Fatalf("escaped duplicate error = %v", err)
	}
}

func TestInvalidUTF8(t *testing.T) {
	if err := Validate([]byte{'{', '"', 'x', '"', ':', '"', 0xff, '"', '}'}); err == nil {
		t.Fatal("invalid UTF-8 accepted")
	}
}

func TestTopLevelMembersIgnoreKeyTextInsideValues(t *testing.T) {
	data := []byte(`{"question":"say \"host_signature\" now","nested":{"host_signature":"fake"},"host_signature":"real"}`)
	members, err := TopLevelMembers(data)
	if err != nil {
		t.Fatal(err)
	}
	if len(members) != 3 || members[2].Key != "host_signature" || string(data[members[2].KeyOffset:members[2].KeyOffset+16]) != `"host_signature"` {
		t.Fatalf("members = %#v", members)
	}
}
