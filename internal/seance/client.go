package seance

import (
	"context"
	"errors"
	"fmt"
	"net"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	"github.com/no-way-labs/cauldron/internal/frame"
	"github.com/no-way-labs/cauldron/internal/secretbox"
)

type ClientConfig struct {
	Address    string
	Nick       string
	Timeout    time.Duration
	TimeoutSet bool
	Now        func() time.Time
	OnEvent    EventHandler
	Retention  int
}

type Client struct {
	connection net.Conn
	key        secretbox.Key
	config     ClientConfig
	writeMu    sync.Mutex
	closeOnce  sync.Once
	running    atomic.Bool

	peersMu sync.RWMutex
	peers   []string
	buffer  *MessageBuffer
}

func Connect(ctx context.Context, config ClientConfig, key *secretbox.Key) (*Client, error) {
	if key == nil {
		return nil, errors.New("seance: key is required")
	}
	if err := validateNick(config.Nick); err != nil {
		return nil, err
	}
	if config.Address == "" {
		return nil, errors.New("seance: address is required")
	}
	if !config.TimeoutSet {
		config.Timeout = 30 * time.Second
	}
	if config.Timeout < 0 {
		return nil, errors.New("seance: timeout cannot be negative")
	}
	if config.Now == nil {
		config.Now = time.Now
	}
	if config.OnEvent == nil {
		config.OnEvent = func(Message) {}
	}
	if config.Retention == 0 {
		config.Retention = DefaultMessageRetention
	}
	if config.Retention < 1 {
		return nil, errors.New("seance: retention must be positive")
	}
	dialer := net.Dialer{Timeout: config.Timeout}
	connection, err := dialer.DialContext(ctx, "tcp", config.Address)
	if err != nil {
		return nil, err
	}
	client := &Client{
		connection: connection, key: *key, config: config,
		buffer: NewMessageBuffer(config.Retention),
	}
	cleanup := func() {
		_ = connection.Close()
		secretbox.ZeroKey(&client.key)
	}
	client.running.Store(true)
	if config.Timeout > 0 {
		if err := connection.SetDeadline(time.Now().Add(config.Timeout)); err != nil {
			cleanup()
			return nil, err
		}
	}
	if err := sendEncrypted(connection, &client.writeMu, &client.key, MessageJoin, config.Nick, []byte(Magic), config.Now()); err != nil {
		cleanup()
		return nil, err
	}
	if err := connection.SetDeadline(time.Time{}); err != nil {
		cleanup()
		return nil, err
	}
	return client, nil
}

func (client *Client) Nick() string { return client.config.Nick }

func (client *Client) Messages() *MessageBuffer { return client.buffer }

func (client *Client) Peers() []string {
	client.peersMu.RLock()
	defer client.peersMu.RUnlock()
	result := make([]string, len(client.peers))
	copy(result, client.peers)
	return result
}

func (client *Client) Running() bool { return client.running.Load() }

func (client *Client) Run(ctx context.Context) error {
	connection := client.connection
	stop := context.AfterFunc(ctx, func() { _ = client.Close() })
	defer stop()
	defer client.Close()
	for client.running.Load() {
		value, err := frame.Read(connection, ValidMessageType)
		if err != nil {
			if ctx.Err() != nil || !client.running.Load() || errors.Is(err, net.ErrClosed) {
				return nil
			}
			return fmt.Errorf("seance: connection lost: %w", err)
		}
		plaintext, openErr := secretbox.Open(&client.key, secretbox.Box{
			Nonce: value.Nonce, Tag: value.Tag, Ciphertext: value.Ciphertext,
		})
		secretbox.Zero(value.Ciphertext)
		if openErr != nil {
			continue
		}
		switch value.Type {
		case MessageChat:
			message := Message{Timestamp: value.Timestamp, Sender: value.Sender, Content: string(plaintext), Type: "msg"}
			client.config.OnEvent(message)
			client.buffer.Append(message)
		case MessageAnnounce:
			content := string(plaintext)
			messageType := "announce"
			if strings.HasSuffix(content, " joined") {
				messageType = "join"
			} else if strings.HasSuffix(content, " left") {
				messageType = "leave"
			}
			message := Message{Timestamp: value.Timestamp, Sender: value.Sender, Content: content, Type: messageType}
			client.config.OnEvent(message)
			client.buffer.Append(message)
			client.updatePeers(content)
		case MessageNickList:
			client.setPeers(parseNickList(plaintext))
			client.config.OnEvent(Message{Timestamp: value.Timestamp, Sender: value.Sender, Content: string(plaintext), Type: "nick_list"})
		default:
			// Known client-inappropriate frame types are ignored for v1 parity.
		}
		secretbox.Zero(plaintext)
	}
	return nil
}

func (client *Client) SendMessage(text string) error {
	if len(text) == 0 {
		return errors.New("seance: message cannot be empty")
	}
	value, err := encryptedFrame(&client.key, MessageChat, client.config.Nick, []byte(text), client.config.Now())
	if err != nil {
		return err
	}
	defer secretbox.Zero(value.Ciphertext)
	if err := writeFrame(client.connection, &client.writeMu, value); err != nil {
		return err
	}
	client.config.OnEvent(Message{Timestamp: value.Timestamp, Sender: client.config.Nick, Content: text, Type: "msg"})
	return nil
}

func (client *Client) SendLeave() error {
	if !client.running.Load() {
		return nil
	}
	return sendEncrypted(client.connection, &client.writeMu, &client.key, MessageLeave, client.config.Nick, []byte("goodbye"), client.config.Now())
}

func (client *Client) setPeers(peers []string) {
	client.peersMu.Lock()
	client.peers = append(client.peers[:0], peers...)
	client.peersMu.Unlock()
}

func (client *Client) updatePeers(content string) {
	client.peersMu.Lock()
	defer client.peersMu.Unlock()
	if strings.HasSuffix(content, " joined") {
		nick := strings.TrimSuffix(content, " joined")
		for _, existing := range client.peers {
			if existing == nick {
				return
			}
		}
		client.peers = append(client.peers, nick)
		return
	}
	if strings.HasSuffix(content, " left") {
		nick := strings.TrimSuffix(content, " left")
		for index, existing := range client.peers {
			if existing == nick {
				client.peers = append(client.peers[:index], client.peers[index+1:]...)
				return
			}
		}
	}
}

func parseNickList(payload []byte) []string {
	parts := strings.Split(string(payload), "\n")
	result := make([]string, 0, len(parts))
	for _, part := range parts {
		if part != "" {
			result = append(result, part)
		}
	}
	return result
}

func (client *Client) Close() error {
	var err error
	client.closeOnce.Do(func() {
		client.running.Store(false)
		client.buffer.Close()
		if client.connection != nil {
			err = client.connection.Close()
		}
	})
	return err
}

// ZeroKey is called after Run has returned and no reader can be using the key.
func (client *Client) ZeroKey() { secretbox.ZeroKey(&client.key) }
