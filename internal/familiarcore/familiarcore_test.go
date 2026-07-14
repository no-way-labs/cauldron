package familiarcore

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"io"
	"net/http"
	"net/http/httptest"
	"sync/atomic"
	"testing"
	"time"
)

func TestMergeRoles(t *testing.T) {
	got := mergeRoles([]ChatMessage{
		{Role: RoleUser, Content: "a"},
		{Role: RoleUser, Content: "b"},
		{Role: RoleAssistant, Content: "c"},
		{Role: RoleAssistant, Content: "d"},
	})
	want := []ChatMessage{
		{Role: RoleUser, Content: "a\nb"},
		{Role: RoleAssistant, Content: "c\nd"},
	}
	if len(got) != len(want) {
		t.Fatalf("merged length = %d", len(got))
	}
	for i := range want {
		if got[i] != want[i] {
			t.Fatalf("merged[%d] = %#v, want %#v", i, got[i], want[i])
		}
	}
}

func TestClaudeRequestShapeAndResponse(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Header.Get("anthropic-version") != "2023-06-01" || r.Header.Get("x-api-key") != "key" {
			t.Errorf("missing Anthropic headers: %v", r.Header)
		}
		var body map[string]any
		if err := json.NewDecoder(r.Body).Decode(&body); err != nil {
			t.Error(err)
			http.Error(w, "bad request", http.StatusBadRequest)
			return
		}
		if body["max_tokens"] != float64(4096) || body["model"] != "test-model" {
			t.Errorf("request body = %#v", body)
		}
		system, ok := body["system"].([]any)
		if !ok || len(system) != 1 {
			t.Errorf("system is not a one-block array: %#v", body["system"])
		}
		messages, ok := body["messages"].([]any)
		if !ok || len(messages) != 2 {
			t.Errorf("role merging failed: %#v", body["messages"])
		}
		w.Header().Set("Content-Type", "application/json")
		io.WriteString(w, `{"content":[{"type":"text","text":"hello"}]}`)
	}))
	defer server.Close()

	config := (Config{
		ClaudeURL: server.URL, HTTPClient: server.Client(), Model: "test-model",
		SystemPrompt: "system",
	}).withDefaults()
	client := &clients{config: config}
	response, err := client.chat(context.Background(), "key", []ChatMessage{
		{Role: RoleUser, Content: "one"},
		{Role: RoleUser, Content: "two"},
		{Role: RoleAssistant, Content: "three"},
	})
	if err != nil {
		t.Fatal(err)
	}
	if response != "hello" {
		t.Fatalf("response = %q", response)
	}
}

func TestClaudeMalformedShapeReturnsError(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		io.WriteString(w, `{"content":"not-an-array"}`)
	}))
	defer server.Close()
	config := (Config{ClaudeURL: server.URL, HTTPClient: server.Client()}).withDefaults()
	_, err := (&clients{config: config}).chat(context.Background(), "key", nil)
	if err == nil {
		t.Fatal("malformed Claude response accepted")
	}
}

func TestRunEndToEndAgainstStubServers(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	sent := make(chan string, 1)
	var polls atomic.Int32
	var keyReads atomic.Int32

	bot := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch r.URL.Path {
		case "/health":
			io.WriteString(w, `{"status":"ok"}`)
		case "/nick":
			io.WriteString(w, `{"nick":"familiar"}`)
		case "/messages":
			if polls.Add(1) == 1 {
				io.WriteString(w, `[{"id":1,"timestamp":1,"sender":"alice","content":"hello","type":"msg"}]`)
			} else {
				io.WriteString(w, `[]`)
			}
		case "/send":
			body, _ := io.ReadAll(r.Body)
			sent <- string(body)
			io.WriteString(w, `{"status":"sent"}`)
		default:
			http.NotFound(w, r)
		}
	}))
	defer bot.Close()

	claude := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Header.Get("x-api-key") == "stale-key" {
			http.Error(w, "expired", http.StatusUnauthorized)
			return
		}
		if r.Header.Get("x-api-key") != "fresh-key" {
			t.Errorf("unexpected refreshed API key %q", r.Header.Get("x-api-key"))
		}
		var body map[string]any
		if err := json.NewDecoder(r.Body).Decode(&body); err != nil {
			t.Error(err)
		}
		messages := body["messages"].([]any)
		first := messages[0].(map[string]any)
		if first["content"] != "alice: hello" || first["role"] != "user" {
			t.Errorf("unexpected Claude history: %#v", messages)
		}
		io.WriteString(w, `{"content":[{"type":"text","text":"hi alice"}]}`)
	}))
	defer claude.Close()

	var logs bytes.Buffer
	done := make(chan error, 1)
	go func() {
		done <- Run(ctx, Config{
			BotBaseURL: bot.URL, ClaudeURL: claude.URL,
			HTTPClient: bot.Client(), Logger: &logs,
			APIKey: func() (string, bool) {
				if keyReads.Add(1) == 1 {
					return "stale-key", true
				}
				return "fresh-key", true
			},
			HealthDelay: time.Nanosecond, PollWait: time.Nanosecond,
			PollErrorDelay: time.Nanosecond, Cooldown: time.Nanosecond,
		})
	}()

	select {
	case message := <-sent:
		if message != "hi alice" {
			t.Fatalf("sent = %q", message)
		}
		cancel()
	case <-time.After(3 * time.Second):
		t.Fatal("familiar did not answer")
	}
	select {
	case err := <-done:
		if !errors.Is(err, context.Canceled) {
			t.Fatalf("Run error = %v", err)
		}
	case <-time.After(3 * time.Second):
		t.Fatal("familiar did not stop")
	}
	if !bytes.Contains(logs.Bytes(), []byte("Joined as: familiar")) {
		t.Fatalf("missing log line: %s", logs.Bytes())
	}
	if keyReads.Load() < 2 {
		t.Fatal("401 response did not refresh ANTHROPIC_API_KEY")
	}
}

func TestReadLimited(t *testing.T) {
	if _, err := readLimited(bytes.NewReader(make([]byte, 5)), 4); err == nil {
		t.Fatal("oversized body accepted")
	}
}

func TestExplicitZeroCooldownIsPreserved(t *testing.T) {
	config := (Config{Cooldown: 0, CooldownSet: true}).withDefaults()
	if config.Cooldown != 0 {
		t.Fatalf("explicit cooldown = %s, want zero", config.Cooldown)
	}
	if got := (Config{}).withDefaults().Cooldown; got != 2*time.Second {
		t.Fatalf("default cooldown = %s, want 2s", got)
	}
}
