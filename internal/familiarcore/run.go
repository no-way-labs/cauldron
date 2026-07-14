package familiarcore

import (
	"context"
	"errors"
	"fmt"
	"net/url"
	"strconv"
	"time"
)

// Run polls a seance bot API until ctx is canceled or an unrecoverable error
// occurs. Standalone callers should map a returned error to a non-zero exit.
func Run(ctx context.Context, input Config) error {
	config := input.withDefaults()
	if config.ContextSize < 1 {
		return errors.New("familiar: context must be at least 1")
	}
	client, err := newClients(config)
	if err != nil {
		return err
	}
	logf(config, "familiar starting")
	logf(config, "Connecting to seance bot at %s", client.botBase)

	key, ok := config.APIKey()
	if !ok || key == "" {
		return errors.New("familiar: ANTHROPIC_API_KEY is required")
	}
	logf(config, "API key loaded.")

	connected := false
	for attempt := 0; attempt < config.HealthAttempts; attempt++ {
		if err := client.botGET(ctx, "/health", nil); err == nil {
			connected = true
			break
		}
		if attempt == 0 {
			logf(config, "Waiting for seance bot...")
		}
		if err := sleepContext(ctx, config.HealthDelay); err != nil {
			return err
		}
	}
	if !connected {
		return fmt.Errorf("familiar: seance bot not reachable at %s", client.botBase)
	}
	logf(config, "Seance bot connected.")

	var nickResponse struct {
		Nick string
	}
	if err := client.botGET(ctx, "/nick", &nickResponse); err != nil {
		return err
	}
	if nickResponse.Nick == "" {
		return errors.New("familiar: bot /nick returned an empty nick")
	}
	myNick := nickResponse.Nick
	logf(config, "Joined as: %s", myNick)
	logf(config, "Listening for messages...")

	var history []ChatMessage
	var lastID uint64
	for {
		if err := ctx.Err(); err != nil {
			return err
		}
		query := url.Values{}
		query.Set("since", strconv.FormatUint(lastID, 10))
		query.Set("wait", strconv.FormatInt(int64(config.PollWait/time.Second), 10))
		var incoming []SeanceMessage
		if err := client.botGET(ctx, "/messages?"+query.Encode(), &incoming); err != nil {
			if ctx.Err() != nil {
				return ctx.Err()
			}
			if err := sleepContext(ctx, config.PollErrorDelay); err != nil {
				return err
			}
			continue
		}

		needsResponse := false
		for _, message := range incoming {
			if message.ID > lastID {
				lastID = message.ID
			}
			if message.Type != "msg" {
				continue
			}
			if message.Sender == myNick {
				history = append(history, ChatMessage{Role: RoleAssistant, Content: message.Content})
			} else {
				history = append(history, ChatMessage{Role: RoleUser, Content: message.Sender + ": " + message.Content})
				needsResponse = true
			}
		}
		if len(history) > config.ContextSize {
			history = append([]ChatMessage(nil), history[len(history)-config.ContextSize:]...)
		}
		if !needsResponse {
			continue
		}

		logf(config, "Calling Claude API...")
		response, err := client.chat(ctx, key, history)
		if errors.Is(err, ErrUnauthorized) {
			refreshed, available := config.APIKey()
			if !available || refreshed == "" {
				logf(config, "API key refresh failed")
				continue
			}
			key = refreshed
			response, err = client.chat(ctx, key, history)
		}
		if err != nil {
			logf(config, "Claude API error: %v", err)
			continue
		}
		if err := client.botPOST(ctx, "/send", []byte(response)); err != nil {
			logf(config, "Failed to send message: %v", err)
			continue
		}
		logf(config, "[familiar] %s", response)
		history = append(history, ChatMessage{Role: RoleAssistant, Content: response})
		if len(history) > config.ContextSize {
			history = append([]ChatMessage(nil), history[len(history)-config.ContextSize:]...)
		}
		if err := sleepContext(ctx, config.Cooldown); err != nil {
			return err
		}
	}
}

func mergeRoles(messages []ChatMessage) []ChatMessage {
	merged := make([]ChatMessage, 0, len(messages))
	for _, message := range messages {
		if len(merged) > 0 && merged[len(merged)-1].Role == message.Role {
			merged[len(merged)-1].Content += "\n" + message.Content
			continue
		}
		merged = append(merged, message)
	}
	return merged
}

func logf(config Config, format string, args ...any) {
	seconds := uint64(config.Now().Unix()) % 86400
	prefix := fmt.Sprintf("[%02d:%02d:%02d] ", seconds/3600, (seconds%3600)/60, seconds%60)
	fmt.Fprintf(config.Logger, prefix+format+"\n", args...)
}

func sleepContext(ctx context.Context, duration time.Duration) error {
	if duration <= 0 {
		return nil
	}
	timer := time.NewTimer(duration)
	defer timer.Stop()
	select {
	case <-ctx.Done():
		return ctx.Err()
	case <-timer.C:
		return nil
	}
}
