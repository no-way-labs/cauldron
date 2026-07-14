package familiarcore

import (
	"io"
	"net/http"
	"os"
	"time"
)

const (
	DefaultModel       = "claude-sonnet-4-5-20250929"
	DefaultContextSize = 50
	DefaultAPIPort     = 9999
	DefaultAPIHost     = "127.0.0.1"

	defaultClaudeURL = "https://api.anthropic.com/v1/messages"
	maxLocalBody     = 2 << 20
	maxClaudeBody    = 8 << 20
)

const defaultPersonality = "You are familiar, a chat bot in a seance room. " +
	"You are friendly, concise, and conversational. Messages from others are formatted as 'nick: message'. " +
	"Respond naturally without prefixing your nick. Keep responses brief unless asked for detail."

type Role string

const (
	RoleUser      Role = "user"
	RoleAssistant Role = "assistant"
)

type ChatMessage struct {
	Role    Role
	Content string
}

type SeanceMessage struct {
	ID      uint64
	Sender  string
	Content string
	Type    string
}

type Config struct {
	APIHost      string
	APIPort      uint16
	SystemPrompt string
	ContextSize  int
	Model        string
	Cooldown     time.Duration
	// CooldownSet distinguishes an explicit zero-second cooldown from an
	// omitted value, which receives the two-second default.
	CooldownSet bool

	// Injectable seams used by embedded familiar and tests.
	BotBaseURL     string
	ClaudeURL      string
	HTTPClient     *http.Client
	Logger         io.Writer
	Now            func() time.Time
	APIKey         func() (string, bool)
	HealthAttempts int
	HealthDelay    time.Duration
	PollWait       time.Duration
	PollErrorDelay time.Duration
}

func (config Config) withDefaults() Config {
	if config.APIHost == "" {
		config.APIHost = DefaultAPIHost
	}
	if config.APIPort == 0 {
		config.APIPort = DefaultAPIPort
	}
	if config.ContextSize == 0 {
		config.ContextSize = DefaultContextSize
	}
	if config.Model == "" {
		config.Model = DefaultModel
	}
	if !config.CooldownSet {
		config.Cooldown = 2 * time.Second
	}
	if config.ClaudeURL == "" {
		config.ClaudeURL = defaultClaudeURL
	}
	if config.HTTPClient == nil {
		config.HTTPClient = &http.Client{Timeout: 2 * time.Minute}
	}
	if config.Logger == nil {
		config.Logger = os.Stderr
	}
	if config.Now == nil {
		config.Now = time.Now
	}
	if config.APIKey == nil {
		config.APIKey = func() (string, bool) {
			value, ok := os.LookupEnv("ANTHROPIC_API_KEY")
			return value, ok && value != ""
		}
	}
	if config.HealthAttempts == 0 {
		config.HealthAttempts = 10
	}
	if config.HealthDelay == 0 {
		config.HealthDelay = time.Second
	}
	if config.PollWait == 0 {
		config.PollWait = 30 * time.Second
	}
	if config.PollErrorDelay == 0 {
		config.PollErrorDelay = 5 * time.Second
	}
	return config
}
