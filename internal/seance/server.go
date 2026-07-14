package seance

import (
	"context"
	"crypto/subtle"
	"errors"
	"fmt"
	"io"
	"net"
	"strings"
	"sync"
	"sync/atomic"
	"time"
	"unicode/utf8"

	"github.com/no-way-labs/cauldron/internal/frame"
	"github.com/no-way-labs/cauldron/internal/secretbox"
)

type ServerConfig struct {
	Port             uint16
	MaxPeers         int
	Nick             string
	Now              func() time.Time
	HandshakeTimeout time.Duration
	WriteTimeout     time.Duration
	OnEvent          EventHandler
	Logger           io.Writer
}

type peer struct {
	connection      net.Conn
	nick            string
	writeMu         sync.Mutex
	messageCount    uint32
	rateWindowStart int64
}

type Server struct {
	listener net.Listener
	config   ServerConfig
	key      secretbox.Key

	mu      sync.Mutex
	peers   []*peer
	running atomic.Bool
	serve   sync.Once
	close   sync.Once
	wg      sync.WaitGroup
	logMu   sync.Mutex
}

func NewServer(config ServerConfig, key *secretbox.Key) (*Server, error) {
	if key == nil {
		return nil, errors.New("seance: key is required")
	}
	if err := validateNick(config.Nick); err != nil {
		return nil, fmt.Errorf("seance: host %w", err)
	}
	if config.MaxPeers == 0 {
		config.MaxPeers = 8
	}
	if config.MaxPeers < 1 || config.MaxPeers > 255 {
		return nil, errors.New("seance: max peers must be 1..255")
	}
	if config.Now == nil {
		config.Now = time.Now
	}
	if config.HandshakeTimeout == 0 {
		config.HandshakeTimeout = 30 * time.Second
	}
	if config.HandshakeTimeout < 0 {
		return nil, errors.New("seance: handshake timeout cannot be negative")
	}
	if config.WriteTimeout == 0 {
		config.WriteTimeout = 5 * time.Second
	}
	if config.WriteTimeout < 0 {
		return nil, errors.New("seance: write timeout cannot be negative")
	}
	if config.OnEvent == nil {
		config.OnEvent = func(Message) {}
	}
	if config.Logger == nil {
		config.Logger = io.Discard
	}
	listener, err := net.Listen("tcp", fmt.Sprintf("127.0.0.1:%d", config.Port))
	if err != nil {
		return nil, err
	}
	server := &Server{listener: listener, config: config, key: *key}
	server.running.Store(true)
	return server, nil
}

func (server *Server) Port() uint16 {
	return uint16(server.listener.Addr().(*net.TCPAddr).Port)
}

func (server *Server) PeerCount() int {
	server.mu.Lock()
	defer server.mu.Unlock()
	return len(server.peers)
}

func (server *Server) Peers() []string {
	server.mu.Lock()
	defer server.mu.Unlock()
	result := make([]string, 0, len(server.peers)+1)
	result = append(result, server.config.Nick)
	for _, peer := range server.peers {
		result = append(result, peer.nick)
	}
	return result
}

func (server *Server) Run(ctx context.Context) error {
	started := false
	server.serve.Do(func() { started = true })
	if !started {
		return errors.New("seance: server Run called more than once")
	}
	stop := context.AfterFunc(ctx, func() { _ = server.Close() })
	defer stop()
	for server.running.Load() {
		connection, err := server.listener.Accept()
		if err != nil {
			if !server.running.Load() || ctx.Err() != nil {
				break
			}
			server.logf("Accept error: %v\n", err)
			continue
		}
		server.wg.Add(1)
		go server.handleConnection(connection)
	}
	_ = server.Close()
	server.wg.Wait()
	secretbox.ZeroKey(&server.key)
	return nil
}

func (server *Server) handleConnection(connection net.Conn) {
	defer server.wg.Done()
	defer connection.Close()
	var admitted *peer
	defer func() {
		if admitted != nil {
			server.removePeer(admitted)
		}
	}()
	if server.config.HandshakeTimeout > 0 {
		if err := connection.SetReadDeadline(time.Now().Add(server.config.HandshakeTimeout)); err != nil {
			return
		}
	}
	join, plaintext, err := readEncrypted(connection, &server.key)
	if err != nil {
		return
	}
	secretbox.Zero(join.Ciphertext)
	defer secretbox.Zero(plaintext)
	if join.Type != MessageJoin || len(plaintext) != len(Magic) || subtle.ConstantTimeCompare(plaintext, []byte(Magic)) != 1 {
		return
	}
	if err := validateNick(join.Sender); err != nil {
		return
	}

	server.mu.Lock()
	if !server.running.Load() || len(server.peers) >= server.config.MaxPeers {
		server.mu.Unlock()
		return
	}
	resolved, err := server.resolveNickLocked(join.Sender)
	if err != nil {
		server.mu.Unlock()
		return
	}
	now := server.config.Now()
	admitted = &peer{connection: connection, nick: resolved, rateWindowStart: now.Unix()}
	server.peers = append(server.peers, admitted)
	server.mu.Unlock()
	if err := connection.SetReadDeadline(time.Time{}); err != nil {
		return
	}
	if err := server.sendNickList(admitted); err != nil {
		return
	}
	server.broadcastAnnouncement(resolved, " joined")
	server.config.OnEvent(Message{Timestamp: uint64(now.Unix()), Sender: "system", Content: resolved + " joined", Type: "join"})

	for server.running.Load() {
		value, err := frame.Read(connection, ValidMessageType)
		if err != nil {
			return
		}
		switch value.Type {
		case MessageChat:
			if !server.allowMessage(admitted) {
				secretbox.Zero(value.Ciphertext)
				continue
			}
			// Protocol v1 deliberately relays the original envelope byte-for-byte,
			// including its unauthenticated sender and timestamp headers.
			server.relay(value, admitted)
			plaintext, openErr := secretbox.Open(&server.key, secretbox.Box{
				Nonce: value.Nonce, Tag: value.Tag, Ciphertext: value.Ciphertext,
			})
			secretbox.Zero(value.Ciphertext)
			if openErr != nil {
				continue
			}
			server.config.OnEvent(Message{
				Timestamp: value.Timestamp, Sender: admitted.nick, Content: string(plaintext), Type: "msg",
			})
			secretbox.Zero(plaintext)
		case MessageLeave:
			secretbox.Zero(value.Ciphertext)
			return
		default:
			// Known but client-inappropriate frame types are ignored for v1 parity.
			secretbox.Zero(value.Ciphertext)
		}
	}
}

func (server *Server) SendMessage(text string) error {
	if len(text) == 0 {
		return errors.New("seance: message cannot be empty")
	}
	value, err := encryptedFrame(&server.key, MessageChat, server.config.Nick, []byte(text), server.config.Now())
	if err != nil {
		return err
	}
	defer secretbox.Zero(value.Ciphertext)
	// A peer may disappear between the snapshot and this write. The legacy host
	// keeps the room alive and delivers to every remaining writable peer.
	_ = server.broadcastFrame(value, nil)
	server.config.OnEvent(Message{Timestamp: value.Timestamp, Sender: server.config.Nick, Content: text, Type: "msg"})
	return nil
}

func (server *Server) relay(value frame.Frame, sender *peer) {
	_ = server.broadcastFrame(value, sender)
}

func (server *Server) broadcastFrame(value frame.Frame, excluded *peer) error {
	server.mu.Lock()
	snapshot := append([]*peer(nil), server.peers...)
	server.mu.Unlock()
	var first error
	for _, recipient := range snapshot {
		if recipient == excluded {
			continue
		}
		err := server.writePeer(recipient, value)
		if err != nil {
			// A failed or timed-out writer must not leave its read goroutine and
			// admission slot pinned indefinitely.
			_ = recipient.connection.Close()
			if first == nil {
				first = err
			}
		}
	}
	return first
}

func (server *Server) writePeer(recipient *peer, value frame.Frame) error {
	recipient.writeMu.Lock()
	defer recipient.writeMu.Unlock()
	if server.config.WriteTimeout > 0 {
		_ = recipient.connection.SetWriteDeadline(time.Now().Add(server.config.WriteTimeout))
		defer recipient.connection.SetWriteDeadline(time.Time{})
	}
	if err := frame.Write(recipient.connection, value, ValidMessageType); err != nil {
		return fmt.Errorf("seance: send frame: %w", err)
	}
	return nil
}

func (server *Server) broadcastAnnouncement(nick, suffix string) {
	content := nick + suffix
	value, err := encryptedFrame(&server.key, MessageAnnounce, "system", []byte(content), server.config.Now())
	if err != nil {
		return
	}
	defer secretbox.Zero(value.Ciphertext)
	_ = server.broadcastFrame(value, nil)
}

func (server *Server) sendNickList(recipient *peer) error {
	peers := server.Peers()
	payload := strings.Join(peers, "\n") + "\n"
	value, err := encryptedFrame(&server.key, MessageNickList, "system", []byte(payload), server.config.Now())
	if err != nil {
		return err
	}
	defer secretbox.Zero(value.Ciphertext)
	return server.writePeer(recipient, value)
}

func (server *Server) allowMessage(candidate *peer) bool {
	server.mu.Lock()
	defer server.mu.Unlock()
	now := server.config.Now().Unix()
	if now < candidate.rateWindowStart || now-candidate.rateWindowStart >= 1 {
		candidate.messageCount = 0
		candidate.rateWindowStart = now
	}
	if candidate.messageCount >= 10 {
		return false
	}
	candidate.messageCount++
	return true
}

func (server *Server) removePeer(target *peer) {
	server.mu.Lock()
	found := false
	for index, candidate := range server.peers {
		if candidate == target {
			server.peers = append(server.peers[:index], server.peers[index+1:]...)
			found = true
			break
		}
	}
	running := server.running.Load()
	server.mu.Unlock()
	if found && running {
		now := server.config.Now()
		server.broadcastAnnouncement(target.nick, " left")
		server.config.OnEvent(Message{Timestamp: uint64(now.Unix()), Sender: "system", Content: target.nick + " left", Type: "leave"})
	}
}

func (server *Server) resolveNickLocked(input string) (string, error) {
	used := func(candidate string) bool {
		if candidate == server.config.Nick {
			return true
		}
		for _, peer := range server.peers {
			if candidate == peer.nick {
				return true
			}
		}
		return false
	}
	if !used(input) {
		return input, nil
	}
	for suffix := 2; suffix < 100; suffix++ {
		ending := fmt.Sprintf("_%d", suffix)
		candidate := truncateUTF8(input, frame.MaxSenderLen-len(ending)) + ending
		if !used(candidate) {
			return candidate, nil
		}
	}
	return "", errors.New("seance: too many nick collisions")
}

func validateNick(value string) error {
	if value == "" || len(value) > frame.MaxSenderLen || !utf8.ValidString(value) || strings.ContainsRune(value, '\n') {
		return fmt.Errorf("nick must be non-empty valid UTF-8 without newlines and at most %d bytes", frame.MaxSenderLen)
	}
	return nil
}

func truncateUTF8(value string, limit int) string {
	if len(value) <= limit {
		return value
	}
	value = value[:limit]
	for !utf8.ValidString(value) {
		value = value[:len(value)-1]
	}
	return value
}

func (server *Server) Close() error {
	var err error
	server.close.Do(func() {
		server.running.Store(false)
		err = server.listener.Close()
		server.mu.Lock()
		snapshot := append([]*peer(nil), server.peers...)
		server.mu.Unlock()
		for _, peer := range snapshot {
			_ = peer.connection.Close()
		}
	})
	if errors.Is(err, net.ErrClosed) {
		return nil
	}
	return err
}

func (server *Server) logf(format string, args ...any) {
	server.logMu.Lock()
	defer server.logMu.Unlock()
	fmt.Fprintf(server.config.Logger, format, args...)
}
