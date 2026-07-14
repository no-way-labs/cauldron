package familiarcore

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/url"
	"strconv"
	"strings"
)

var (
	ErrUnauthorized = errors.New("familiar: Anthropic API key unauthorized")
	ErrNoText       = errors.New("familiar: Claude response has no text block")
)

type clients struct {
	config  Config
	botBase string
}

func newClients(config Config) (*clients, error) {
	base := config.BotBaseURL
	if base == "" {
		base = "http://" + net.JoinHostPort(config.APIHost, strconv.Itoa(int(config.APIPort)))
	}
	parsed, err := url.Parse(base)
	if err != nil || parsed.Scheme == "" || parsed.Host == "" {
		return nil, fmt.Errorf("familiar: invalid bot API URL %q", base)
	}
	return &clients{config: config, botBase: strings.TrimRight(base, "/")}, nil
}

func (client *clients) botGET(ctx context.Context, path string, target any) error {
	request, err := http.NewRequestWithContext(ctx, http.MethodGet, client.botBase+path, nil)
	if err != nil {
		return err
	}
	request.Close = true
	response, err := client.config.HTTPClient.Do(request)
	if err != nil {
		return err
	}
	defer response.Body.Close()
	if response.StatusCode < 200 || response.StatusCode >= 300 {
		return fmt.Errorf("familiar: bot GET %s returned %s", path, response.Status)
	}
	if target == nil {
		_, err = readLimited(response.Body, maxLocalBody)
		return err
	}
	body, err := readLimited(response.Body, maxLocalBody)
	if err != nil {
		return err
	}
	decoder := json.NewDecoder(bytes.NewReader(body))
	if err := decoder.Decode(target); err != nil {
		return fmt.Errorf("familiar: decode bot response: %w", err)
	}
	if err := decoder.Decode(&struct{}{}); err != io.EOF {
		return errors.New("familiar: trailing bot JSON")
	}
	return nil
}

func (client *clients) botPOST(ctx context.Context, path string, body []byte) error {
	request, err := http.NewRequestWithContext(ctx, http.MethodPost, client.botBase+path, bytes.NewReader(body))
	if err != nil {
		return err
	}
	request.Close = true
	response, err := client.config.HTTPClient.Do(request)
	if err != nil {
		return err
	}
	defer response.Body.Close()
	responseBody, readErr := readLimited(response.Body, maxLocalBody)
	if readErr != nil {
		return readErr
	}
	if response.StatusCode != http.StatusOK {
		return fmt.Errorf("familiar: bot POST %s returned %s: %s", path, response.Status, responseBody)
	}
	return nil
}

type contentBlock struct {
	Type string
	Text string
}

type claudeResponse struct {
	Content []contentBlock
}

func (client *clients) chat(ctx context.Context, key string, history []ChatMessage) (string, error) {
	system := client.config.SystemPrompt
	if system == "" {
		system = defaultPersonality
	}
	merged := mergeRoles(history)
	wireMessages := make([]map[string]string, 0, len(merged))
	for _, message := range merged {
		wireMessages = append(wireMessages, map[string]string{
			"role": string(message.Role), "content": message.Content,
		})
	}
	payload, err := json.Marshal(map[string]any{
		"model":      client.config.Model,
		"max_tokens": 4096,
		"system": []map[string]string{{
			"type": "text", "text": system,
		}},
		"messages": wireMessages,
	})
	if err != nil {
		return "", err
	}

	var lastErr error
	for attempt := 0; attempt < 2; attempt++ {
		request, err := http.NewRequestWithContext(ctx, http.MethodPost, client.config.ClaudeURL, bytes.NewReader(payload))
		if err != nil {
			return "", err
		}
		request.Header.Set("Content-Type", "application/json")
		request.Header.Set("Accept-Encoding", "identity")
		request.Header.Set("anthropic-version", "2023-06-01")
		request.Header.Set("x-api-key", key)
		response, err := client.config.HTTPClient.Do(request)
		if err != nil {
			lastErr = err
			continue
		}
		body, readErr := readLimited(response.Body, maxClaudeBody)
		response.Body.Close()
		if readErr != nil {
			return "", readErr
		}
		if response.StatusCode == http.StatusUnauthorized {
			return "", ErrUnauthorized
		}
		if response.StatusCode != http.StatusOK {
			return "", fmt.Errorf("familiar: Claude API %s: %s", response.Status, body)
		}
		var decoded claudeResponse
		if err := json.Unmarshal(body, &decoded); err != nil {
			return "", fmt.Errorf("familiar: decode Claude response: %w", err)
		}
		for _, block := range decoded.Content {
			if block.Type == "text" && block.Text != "" {
				return block.Text, nil
			}
		}
		return "", ErrNoText
	}
	return "", fmt.Errorf("familiar: Claude request failed after retry: %w", lastErr)
}

func readLimited(reader io.Reader, limit int64) ([]byte, error) {
	data, err := io.ReadAll(io.LimitReader(reader, limit+1))
	if err != nil {
		return nil, err
	}
	if int64(len(data)) > limit {
		return nil, fmt.Errorf("familiar: HTTP body exceeds %d bytes", limit)
	}
	return data, nil
}
