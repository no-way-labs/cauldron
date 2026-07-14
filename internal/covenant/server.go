package covenant

import (
	"context"
	"crypto/rand"
	"crypto/subtle"
	"errors"
	"fmt"
	"io"
	"net"
	"sync"
	"time"
	"unicode/utf8"

	"github.com/no-way-labs/cauldron/internal/frame"
	"github.com/no-way-labs/cauldron/internal/secretbox"
	"github.com/no-way-labs/cauldron/internal/sigcrypto"
)

var (
	ErrAborted  = errors.New("covenant: ceremony aborted")
	ErrNotReady = errors.New("covenant: members are not ready to seal")
)

type ServerConfig struct {
	Port             uint16
	MaxRemoteMembers int
	Nick             string
	GroupName        string
	Version          string
	Logger           io.Writer
	Now              func() time.Time
	Random           io.Reader
	HandshakeTimeout time.Duration
	DeliveryTimeout  time.Duration
}

type ceremonyResult struct {
	artifact []byte
	err      error
}

type remoteMember struct {
	connection net.Conn
	nick       string
	writeMu    sync.Mutex
	publicKey  sigcrypto.PublicKey
	hasKey     bool
	signature  sigcrypto.Signature
	hasSig     bool
}

type Server struct {
	listener net.Listener
	config   ServerConfig
	key      secretbox.Key
	identity *sigcrypto.KeyPair
	session  sigcrypto.Hash

	mu            sync.Mutex
	phase         byte
	members       []*remoteMember
	roster        []Member
	rosterHash    sigcrypto.Hash
	hostSignature sigcrypto.Signature
	hostSigned    bool

	done       chan struct{}
	doneOnce   sync.Once
	resultMu   sync.Mutex
	result     ceremonyResult
	terminalMu sync.Mutex
	serve      sync.Once
	wg         sync.WaitGroup
	logMu      sync.Mutex
}

func NewServer(config ServerConfig, key *secretbox.Key, identity *sigcrypto.KeyPair) (*Server, error) {
	if key == nil || identity == nil {
		return nil, errors.New("covenant: key and identity are required")
	}
	if err := validateNick(config.Nick); err != nil {
		return nil, fmt.Errorf("covenant: host %w", err)
	}
	if config.GroupName == "" || !utf8.ValidString(config.GroupName) || len(config.GroupName) > frame.MaxPayloadLen {
		return nil, errors.New("covenant: group name must be non-empty valid UTF-8 within the frame limit")
	}
	if config.Version == "" || !utf8.ValidString(config.Version) {
		return nil, errors.New("covenant: version is required")
	}
	if config.MaxRemoteMembers == 0 {
		config.MaxRemoteMembers = 32
	}
	if config.MaxRemoteMembers < 1 || config.MaxRemoteMembers > 254 {
		return nil, errors.New("covenant: max remote members must be 1..254")
	}
	if config.Logger == nil {
		config.Logger = io.Discard
	}
	if config.Now == nil {
		config.Now = time.Now
	}
	if config.Random == nil {
		config.Random = rand.Reader
	}
	if config.HandshakeTimeout == 0 {
		config.HandshakeTimeout = 30 * time.Second
	}
	if config.HandshakeTimeout < 0 {
		return nil, errors.New("covenant: handshake timeout cannot be negative")
	}
	if config.DeliveryTimeout == 0 {
		config.DeliveryTimeout = 5 * time.Second
	}
	if config.DeliveryTimeout < 0 {
		return nil, errors.New("covenant: delivery timeout cannot be negative")
	}
	listener, err := net.Listen("tcp", fmt.Sprintf("127.0.0.1:%d", config.Port))
	if err != nil {
		return nil, err
	}
	server := &Server{
		listener: listener, config: config, key: *key, identity: identity,
		phase: PhaseLobby, done: make(chan struct{}),
	}
	if _, err := io.ReadFull(config.Random, server.session[:]); err != nil {
		listener.Close()
		secretbox.ZeroKey(&server.key)
		return nil, fmt.Errorf("covenant: generate session id: %w", err)
	}
	return server, nil
}

func (server *Server) Port() uint16 {
	return uint16(server.listener.Addr().(*net.TCPAddr).Port)
}

func (server *Server) Ready() (connected, keyed int) {
	server.mu.Lock()
	defer server.mu.Unlock()
	for _, member := range server.members {
		if member.hasKey {
			keyed++
		}
	}
	return len(server.members), keyed
}

// Run accepts and serves members until Seal completes, Abort is called, or ctx
// is canceled. The returned artifact is already self-verified.
func (server *Server) Run(ctx context.Context) ([]byte, error) {
	started := false
	server.serve.Do(func() {
		started = true
		server.wg.Add(1)
		go server.acceptLoop()
	})
	if !started {
		return nil, errors.New("covenant: server Run called more than once")
	}
	stop := context.AfterFunc(ctx, func() { server.fail(ctx.Err()) })
	defer stop()
	select {
	case <-server.done:
	case <-ctx.Done():
		<-server.done
	}
	_ = server.listener.Close()
	server.closeMembers()
	server.wg.Wait()
	secretbox.ZeroKey(&server.key)
	server.resultMu.Lock()
	defer server.resultMu.Unlock()
	return append([]byte(nil), server.result.artifact...), server.result.err
}

func (server *Server) acceptLoop() {
	defer server.wg.Done()
	for {
		connection, err := server.listener.Accept()
		if err != nil {
			server.mu.Lock()
			phase := server.phase
			server.mu.Unlock()
			if phase != PhaseLobby {
				return
			}
			select {
			case <-server.done:
				return
			default:
				server.fail(fmt.Errorf("covenant: accept: %w", err))
				return
			}
		}
		server.wg.Add(1)
		go server.handleConnection(connection)
	}
}

func (server *Server) handleConnection(connection net.Conn) {
	defer server.wg.Done()
	admitted := false
	var member *remoteMember
	defer func() {
		connection.Close()
		if admitted {
			server.memberDisconnected(member)
		}
	}()
	if err := connection.SetReadDeadline(time.Now().Add(server.config.HandshakeTimeout)); err != nil {
		return
	}
	join, plaintext, err := readEncrypted(connection, &server.key)
	if err != nil {
		return
	}
	defer secretbox.Zero(plaintext)
	if join.Type != MessageJoin || len(plaintext) != len(Magic) || subtle.ConstantTimeCompare(plaintext, []byte(Magic)) != 1 {
		return
	}
	if err := validateNick(join.Sender); err != nil {
		return
	}

	server.mu.Lock()
	if server.phase != PhaseLobby || len(server.members) >= server.config.MaxRemoteMembers {
		server.mu.Unlock()
		return
	}
	resolved, err := server.resolveNickLocked(join.Sender)
	if err != nil {
		server.mu.Unlock()
		return
	}
	member = &remoteMember{connection: connection, nick: resolved}
	server.members = append(server.members, member)
	count := len(server.members) + 1
	server.mu.Unlock()
	admitted = true
	if err := connection.SetReadDeadline(time.Time{}); err != nil {
		return
	}
	server.logf("* %s joined (%d members)\n", member.nick, count)
	if err := server.sendMember(member, MessagePhase, []byte(server.config.GroupName)); err != nil {
		return
	}

	for {
		value, payload, err := readEncrypted(connection, &server.key)
		if err != nil {
			return
		}
		handleErr := server.handleMemberMessage(member, value.Type, payload)
		secretbox.Zero(payload)
		if handleErr != nil {
			if errors.Is(handleErr, ErrAborted) {
				server.fail(handleErr)
			}
			return
		}
		if value.Type == MessageLeave {
			return
		}
	}
}

func (server *Server) handleMemberMessage(member *remoteMember, messageType byte, payload []byte) error {
	switch messageType {
	case MessagePublicKey:
		if len(payload) != sigcrypto.PublicKeySize {
			return errors.New("covenant: invalid public key payload")
		}
		var publicKey sigcrypto.PublicKey
		copy(publicKey[:], payload)
		server.mu.Lock()
		defer server.mu.Unlock()
		if server.phase != PhaseLobby || member.hasKey || publicKey == server.identity.Public() {
			return errors.New("covenant: invalid or duplicate member identity")
		}
		for _, existing := range server.members {
			if existing != member && existing.hasKey && existing.publicKey == publicKey {
				return errors.New("covenant: duplicate member identity")
			}
		}
		member.publicKey, member.hasKey = publicKey, true
		return nil
	case MessageSignature:
		if len(payload) != sigcrypto.SignatureSize {
			return ErrAborted
		}
		var signature sigcrypto.Signature
		copy(signature[:], payload)
		server.mu.Lock()
		if server.phase != PhaseSeal || !member.hasKey || member.hasSig ||
			!sigcrypto.VerifyCovenantRoster(member.publicKey, server.rosterHash, signature) {
			server.mu.Unlock()
			return ErrAborted
		}
		member.signature, member.hasSig = signature, true
		received, total := server.signatureCountLocked(), len(server.members)+1
		complete := received == total
		server.mu.Unlock()
		server.logf("Collecting signatures... (%d/%d)\n", received, total)
		if complete {
			server.finish()
		}
		return nil
	case MessageLeave:
		return nil
	case MessageAbort:
		return ErrAborted
	default:
		return errors.New("covenant: unexpected member message")
	}
}

// Seal freezes a canonical roster and starts signature collection.
func (server *Server) Seal() error {
	server.terminalMu.Lock()
	defer server.terminalMu.Unlock()
	select {
	case <-server.done:
		return ErrAborted
	default:
	}
	server.mu.Lock()
	if server.phase != PhaseLobby || len(server.members) == 0 {
		server.mu.Unlock()
		return ErrNotReady
	}
	members := make([]sigcrypto.CovenantMember, 0, len(server.members)+1)
	members = append(members, sigcrypto.CovenantMember{Nick: server.config.Nick, PublicKey: server.identity.Public()})
	for _, member := range server.members {
		if !member.hasKey {
			server.mu.Unlock()
			return ErrNotReady
		}
		members = append(members, sigcrypto.CovenantMember{Nick: member.nick, PublicKey: member.publicKey})
	}
	rosterHash, sorted, err := sigcrypto.CovenantRosterHash(members)
	if err != nil {
		server.mu.Unlock()
		return err
	}
	roster := make([]Member, len(sorted))
	for index, member := range sorted {
		roster[index] = Member{Nick: member.Nick, PublicKey: member.PublicKey}
	}
	rosterPayload, err := EncodeRoster(roster)
	if err != nil {
		server.mu.Unlock()
		return err
	}
	if err := preflightArtifact(server.config.Version, server.config.GroupName, server.config.Now(), server.session, rosterHash, roster); err != nil {
		server.mu.Unlock()
		return err
	}
	hostSignature, err := sigcrypto.SignCovenantRoster(server.identity, rosterHash)
	if err != nil {
		server.mu.Unlock()
		return err
	}
	server.phase, server.roster, server.rosterHash = PhaseSeal, roster, rosterHash
	server.hostSignature, server.hostSigned = hostSignature, true
	snapshot := append([]*remoteMember(nil), server.members...)
	server.mu.Unlock()
	_ = server.listener.Close()

	server.logf("\n--- Sealing covenant (%d members) ---\n", len(roster))
	if err := server.deliverMembers(snapshot, MessageRoster, rosterPayload); err != nil {
		server.failLocked(ErrAborted)
		return err
	}
	phase, _ := EncodePhase(PhaseSeal)
	if err := server.deliverMembers(snapshot, MessagePhase, phase); err != nil {
		server.failLocked(ErrAborted)
		return err
	}
	server.logf("Collecting signatures... (1/%d)\n", len(roster))
	return nil
}

func (server *Server) finish() {
	server.mu.Lock()
	if server.phase != PhaseSeal || server.signatureCountLocked() != len(server.members)+1 {
		server.mu.Unlock()
		return
	}
	signatures := make(map[sigcrypto.PublicKey]sigcrypto.Signature, len(server.members)+1)
	signatures[server.identity.Public()] = server.hostSignature
	for _, member := range server.members {
		signatures[member.publicKey] = member.signature
	}
	signed := make([]SignedMember, len(server.roster))
	for index, member := range server.roster {
		signed[index] = SignedMember{Nick: member.Nick, PublicKey: member.PublicKey, Signature: signatures[member.PublicKey]}
	}
	artifact := Artifact{
		Version: server.config.Version, GroupName: server.config.GroupName,
		CreatedAt: uint64(server.config.Now().Unix()), SessionID: server.session,
		RosterHash: server.rosterHash, Members: signed, MemberCount: len(signed),
	}
	snapshot := append([]*remoteMember(nil), server.members...)
	server.mu.Unlock()
	encoded, err := BuildArtifact(artifact)
	if err != nil {
		server.fail(err)
		return
	}
	verified, err := VerifyArtifact(encoded)
	if err != nil || !verified.Valid {
		server.fail(errors.New("covenant: generated artifact failed self-verification"))
		return
	}
	server.terminalMu.Lock()
	defer server.terminalMu.Unlock()
	select {
	case <-server.done:
		return
	default:
	}
	server.mu.Lock()
	server.phase = PhaseDone
	server.mu.Unlock()
	if err := server.deliverMembers(snapshot, MessageCovenant, encoded); err != nil {
		server.complete(nil, fmt.Errorf("covenant: deliver final artifact: %w", err))
		return
	}
	server.logf("\n  COVENANT SEALED  %d members signed\n\n", len(signed))
	server.complete(encoded, nil)
}

func (server *Server) Abort() { server.fail(ErrAborted) }

func (server *Server) fail(err error) {
	server.terminalMu.Lock()
	defer server.terminalMu.Unlock()
	server.failLocked(err)
}

func (server *Server) failLocked(err error) {
	if err == nil {
		err = ErrAborted
	}
	select {
	case <-server.done:
		return
	default:
	}
	server.mu.Lock()
	if server.phase != PhaseDone {
		server.phase = PhaseDone
	}
	snapshot := append([]*remoteMember(nil), server.members...)
	server.mu.Unlock()
	var group sync.WaitGroup
	for _, member := range snapshot {
		group.Add(1)
		go func(member *remoteMember) {
			defer group.Done()
			_ = server.sendMemberWithTimeout(member, MessageAbort, []byte("aborted"), 250*time.Millisecond)
		}(member)
	}
	group.Wait()
	server.complete(nil, err)
}

func (server *Server) complete(artifact []byte, err error) {
	server.doneOnce.Do(func() {
		server.resultMu.Lock()
		server.result = ceremonyResult{artifact: append([]byte(nil), artifact...), err: err}
		server.resultMu.Unlock()
		close(server.done)
	})
}

func (server *Server) signatureCountLocked() int {
	count := 0
	if server.hostSigned {
		count++
	}
	for _, member := range server.members {
		if member.hasSig {
			count++
		}
	}
	return count
}

func (server *Server) memberDisconnected(member *remoteMember) {
	server.mu.Lock()
	phase := server.phase
	if phase == PhaseLobby {
		for index, candidate := range server.members {
			if candidate == member {
				server.members = append(server.members[:index], server.members[index+1:]...)
				break
			}
		}
		count := len(server.members) + 1
		server.mu.Unlock()
		server.logf("* %s left (%d members)\n", member.nick, count)
		return
	}
	server.mu.Unlock()
	if phase == PhaseSeal {
		server.fail(ErrAborted)
	}
}

func (server *Server) resolveNickLocked(input string) (string, error) {
	used := func(candidate string) bool {
		if candidate == server.config.Nick {
			return true
		}
		for _, member := range server.members {
			if candidate == member.nick {
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
		base := truncateUTF8(input, frame.MaxSenderLen-len(ending))
		candidate := base + ending
		if !used(candidate) {
			return candidate, nil
		}
	}
	return "", errors.New("covenant: too many nick collisions")
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

func (server *Server) closeMembers() {
	server.mu.Lock()
	snapshot := append([]*remoteMember(nil), server.members...)
	server.mu.Unlock()
	for _, member := range snapshot {
		member.connection.Close()
	}
}

func (server *Server) sendMember(member *remoteMember, messageType byte, payload []byte) error {
	return server.sendMemberWithTimeout(member, messageType, payload, server.config.DeliveryTimeout)
}

func (server *Server) sendMemberWithTimeout(member *remoteMember, messageType byte, payload []byte, timeout time.Duration) error {
	member.writeMu.Lock()
	defer member.writeMu.Unlock()
	if timeout > 0 {
		_ = member.connection.SetWriteDeadline(time.Now().Add(timeout))
		defer member.connection.SetWriteDeadline(time.Time{})
	}
	return sendEncrypted(member.connection, nil, &server.key, messageType, "system", payload, server.config.Now())
}

func (server *Server) deliverMembers(members []*remoteMember, messageType byte, payload []byte) error {
	errorsFound := make(chan error, len(members))
	var group sync.WaitGroup
	for _, member := range members {
		group.Add(1)
		go func(member *remoteMember) {
			defer group.Done()
			if err := server.sendMember(member, messageType, payload); err != nil {
				errorsFound <- err
			}
		}(member)
	}
	group.Wait()
	close(errorsFound)
	for err := range errorsFound {
		return err
	}
	return nil
}

func (server *Server) logf(format string, args ...any) {
	server.logMu.Lock()
	defer server.logMu.Unlock()
	fmt.Fprintf(server.config.Logger, format, args...)
}

func preflightArtifact(version, group string, now time.Time, session, rosterHash sigcrypto.Hash, roster []Member) error {
	members := make([]SignedMember, len(roster))
	for index, member := range roster {
		members[index] = SignedMember{Nick: member.Nick, PublicKey: member.PublicKey}
	}
	length := artifactEncodedSize(Artifact{
		Version: version, GroupName: group, CreatedAt: uint64(now.Unix()), SessionID: session,
		RosterHash: rosterHash, Members: members, MemberCount: len(members),
	})
	if length > frame.MaxPayloadLen {
		return fmt.Errorf("covenant: final artifact would be %d bytes, exceeding frame limit", length)
	}
	return nil
}

func artifactEncodedSize(artifact Artifact) int {
	// Fixed writer punctuation plus variable escaped strings and decimal fields.
	length := len(`{"covenant_version":"`) + escapedLength(artifact.Version) +
		len(`","group_name":"`) + escapedLength(artifact.GroupName) +
		len(`","created_at":`) + len(fmt.Sprintf("%d", artifact.CreatedAt)) +
		len(`,"session_id":"`) + 64 + len(`","roster_hash":"`) + 64 + len(`","members":[`)
	for index, member := range artifact.Members {
		if index > 0 {
			length++
		}
		length += len(`{"nick":"`) + escapedLength(member.Nick) + len(`","pubkey":"`) + 64 + len(`","signature":"`) + 128 + len(`"}`)
	}
	return length + len(`],"member_count":`) + len(fmt.Sprintf("%d", len(artifact.Members))) + 1
}

func escapedLength(value string) int {
	length := 0
	for _, character := range []byte(value) {
		switch character {
		case '"', '\\', '\n', '\r', '\t':
			length += 2
		default:
			if character < 0x20 {
				length += 6
			} else {
				length++
			}
		}
	}
	return length
}
