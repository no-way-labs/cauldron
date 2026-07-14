package mitt

import (
	"bytes"
	"context"
	"encoding/binary"
	"errors"
	"fmt"
	"io"
	"net"
	"strings"
	"sync"
	"time"

	"github.com/no-way-labs/cauldron/internal/secretbox"
)

const (
	DefaultMaxSize = uint64(100 << 20)
	maxConnections = 5
	maxPerMinute   = 10
	maxFilename    = 1024
)

type ServerConfig struct {
	Dir      string
	ToStdout bool
	Stdout   io.Writer
	Logger   io.Writer
	Accept   []string
	Reject   []string
	MaxSize  uint64

	ReadTimeout time.Duration
	Now         func() time.Time
}

func DefaultServerConfig() ServerConfig {
	return ServerConfig{
		Dir: "./inbox", Stdout: io.Discard, Logger: io.Discard,
		MaxSize: DefaultMaxSize, ReadTimeout: 120 * time.Second, Now: time.Now,
	}
}

type connectionRecord struct {
	count int
	start time.Time
}

type Server struct {
	listener net.Listener
	key      secretbox.Key
	config   ServerConfig
	port     uint16

	active chan struct{}
	wg     sync.WaitGroup
	close  sync.Once

	rateMu sync.Mutex
	rates  map[string]connectionRecord
	logMu  sync.Mutex
	outMu  sync.Mutex
}

// NewServer binds only loopback, matching the Zig host's bore-facing design.
func NewServer(port uint16, config ServerConfig, key *secretbox.Key) (*Server, error) {
	if key == nil {
		return nil, errors.New("mitt: nil encryption key")
	}
	if config.MaxSize > MaxPayloadBytes {
		return nil, fmt.Errorf("mitt: max size %d exceeds hard cap %d", config.MaxSize, MaxPayloadBytes)
	}
	if config.Dir == "" {
		config.Dir = "./inbox"
	}
	if config.Stdout == nil {
		config.Stdout = io.Discard
	}
	if config.Logger == nil {
		config.Logger = io.Discard
	}
	if config.ReadTimeout == 0 {
		config.ReadTimeout = 120 * time.Second
	}
	if config.ReadTimeout < 0 {
		return nil, errors.New("mitt: read timeout cannot be negative")
	}
	if config.Now == nil {
		config.Now = time.Now
	}
	listener, err := net.Listen("tcp", fmt.Sprintf("127.0.0.1:%d", port))
	if err != nil {
		return nil, err
	}
	actualPort := listener.Addr().(*net.TCPAddr).Port
	return &Server{
		listener: listener, key: *key, config: config, port: uint16(actualPort),
		active: make(chan struct{}, maxConnections), rates: make(map[string]connectionRecord),
	}, nil
}

func (server *Server) Port() uint16 { return server.port }

// Serve accepts until ctx cancellation or Close. Each admitted transfer runs
// concurrently, with a real five-connection ceiling.
func (server *Server) Serve(ctx context.Context) error {
	defer secretbox.ZeroKey(&server.key)
	defer server.wg.Wait()
	server.logf("Server listening on port %d\n", server.port)
	closed := make(chan struct{})
	defer close(closed)
	go func() {
		select {
		case <-ctx.Done():
			_ = server.Close()
		case <-closed:
		}
	}()
	for {
		connection, err := server.listener.Accept()
		if err != nil {
			if ctx.Err() != nil || errors.Is(err, net.ErrClosed) {
				return nil
			}
			_ = server.Close()
			return err
		}
		select {
		case server.active <- struct{}{}:
		default:
			server.logf("Connection limit reached, rejecting connection\n")
			_ = connection.Close()
			continue
		}
		ip := peerIP(connection.RemoteAddr())
		if !server.allow(ip) {
			<-server.active
			server.logf("Rate limit exceeded for %s\n", ip)
			_ = connection.Close()
			continue
		}
		server.wg.Add(1)
		go func() {
			defer server.wg.Done()
			defer func() { <-server.active }()
			defer connection.Close()
			if err := server.handle(connection); err != nil {
				server.logf("Error handling connection: %v\n", err)
			}
		}()
	}
}

func (server *Server) Close() error {
	var err error
	server.close.Do(func() { err = server.listener.Close() })
	return err
}

func (server *Server) handle(connection net.Conn) error {
	if server.config.ReadTimeout > 0 {
		if err := connection.SetReadDeadline(time.Now().Add(server.config.ReadTimeout)); err != nil {
			return err
		}
	}
	var filenameSize [2]byte
	if _, err := io.ReadFull(connection, filenameSize[:]); err != nil {
		return err
	}
	filenameLength := binary.BigEndian.Uint16(filenameSize[:])
	if filenameLength == 0 || filenameLength > maxFilename {
		return errors.New("invalid filename")
	}
	filenameBytes := make([]byte, filenameLength)
	if _, err := io.ReadFull(connection, filenameBytes); err != nil {
		return err
	}
	filename := sanitizeFilename(string(filenameBytes))
	if filename == "" {
		server.logf("Rejected: invalid filename\n")
		return errors.New("invalid filename")
	}

	var sizeBytes [8]byte
	if _, err := io.ReadFull(connection, sizeBytes[:]); err != nil {
		return err
	}
	ciphertextSize := binary.BigEndian.Uint64(sizeBytes[:])
	if ciphertextSize == 0 || ciphertextSize > MaxPayloadBytes {
		server.logf("Rejected: invalid size %d bytes (max: %d bytes)\n", ciphertextSize, MaxPayloadBytes)
		return errors.New("invalid size")
	}
	switch result := checkFilter(filename, ciphertextSize, server.config); result.reason {
	case filterExtension:
		server.logf("Rejected: file type not accepted: %s\n", result.pattern)
		return errors.New("rejected extension")
	case filterSize:
		server.logf("Rejected: max size %dmb, got %dmb\n", server.config.MaxSize/(1024*1024), ciphertextSize/(1024*1024))
		return errors.New("rejected size")
	}

	box := secretbox.Box{Ciphertext: make([]byte, int(ciphertextSize))}
	defer secretbox.Zero(box.Ciphertext)
	if _, err := io.ReadFull(connection, box.Nonce[:]); err != nil {
		return err
	}
	if _, err := io.ReadFull(connection, box.Tag[:]); err != nil {
		return err
	}
	if _, err := io.ReadFull(connection, box.Ciphertext); err != nil {
		return err
	}
	plaintext, err := secretbox.Open(&server.key, box)
	if err != nil {
		time.Sleep(100 * time.Millisecond)
		server.logf("Authentication failed\n")
		return errors.New("authentication failed")
	}
	defer secretbox.Zero(plaintext)

	if server.config.ToStdout {
		server.outMu.Lock()
		_, err = io.Copy(server.config.Stdout, bytes.NewReader(plaintext))
		server.outMu.Unlock()
		if err != nil {
			return err
		}
	} else {
		result, saveErr := save(server.config.Dir, filename, bytes.NewReader(plaintext))
		if saveErr != nil {
			return saveErr
		}
		server.logf("Received: %s (%d bytes) -> %s\n", filename, result.bytes, result.path)
	}
	return writeParts(connection, []byte{0})
}

func sanitizeFilename(filename string) string {
	if index := strings.LastIndexAny(filename, "/\\"); index >= 0 {
		filename = filename[index+1:]
	}
	if filename == "" || filename[0] == '.' || strings.Contains(filename, "..") {
		return ""
	}
	for _, character := range []byte(filename) {
		if (character >= 'a' && character <= 'z') ||
			(character >= 'A' && character <= 'Z') ||
			(character >= '0' && character <= '9') ||
			character == '-' || character == '_' || character == '.' {
			continue
		}
		return ""
	}
	return filename
}

func peerIP(address net.Addr) string {
	host, _, err := net.SplitHostPort(address.String())
	if err != nil {
		return "unknown"
	}
	return host
}

func (server *Server) allow(ip string) bool {
	now := server.config.Now()
	server.rateMu.Lock()
	defer server.rateMu.Unlock()
	record, exists := server.rates[ip]
	if !exists || now.Sub(record.start) >= time.Minute || now.Before(record.start) {
		server.rates[ip] = connectionRecord{count: 1, start: now}
		return true
	}
	if record.count >= maxPerMinute {
		return false
	}
	record.count++
	server.rates[ip] = record
	return true
}

func (server *Server) logf(format string, args ...any) {
	server.logMu.Lock()
	defer server.logMu.Unlock()
	fmt.Fprintf(server.config.Logger, format, args...)
}
