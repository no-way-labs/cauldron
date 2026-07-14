package omen

import (
	"context"
	"crypto/rand"
	"crypto/subtle"
	"errors"
	"fmt"
	"io"
	"math/big"
	"net"
	"strconv"
	"sync"
	"time"
	"unicode/utf8"

	"github.com/no-way-labs/cauldron/internal/frame"
	"github.com/no-way-labs/cauldron/internal/secretbox"
	"github.com/no-way-labs/cauldron/internal/sigcrypto"
)

var (
	ErrAborted  = errors.New("omen: vote aborted")
	ErrNotReady = errors.New("omen: voters are not ready")
)

type ServerConfig struct {
	Port              uint16
	MaxRemoteVoters   int
	Nick              string
	Question          string
	Options           []string
	Version           string
	AllowedPublicKeys []sigcrypto.PublicKey
	Logger            io.Writer
	Now               func() time.Time
	Random            io.Reader
	HandshakeTimeout  time.Duration
	DeliveryTimeout   time.Duration
}

type voteResult struct {
	artifact []byte
	err      error
}

type remoteVoter struct {
	connection net.Conn
	nick       string
	slot       byte
	writeMu    sync.Mutex
	publicKey  sigcrypto.PublicKey
	hasKey     bool
	commitment Commitment
	hasCommit  bool
	reveal     Reveal
	hasReveal  bool
}

type Server struct {
	listener net.Listener
	config   ServerConfig
	key      secretbox.Key
	identity *sigcrypto.KeyPair
	ballot   Ballot

	mu             sync.Mutex
	phase          byte
	voters         []*remoteVoter
	roster         []Peer
	rosterHash     sigcrypto.Hash
	hostCommitment Commitment
	hostReveal     Reveal
	hostVoted      bool
	advancing      bool

	done       chan struct{}
	doneOnce   sync.Once
	resultMu   sync.Mutex
	result     voteResult
	terminalMu sync.Mutex
	serve      sync.Once
	wg         sync.WaitGroup
	logMu      sync.Mutex
}

func NewServer(config ServerConfig, key *secretbox.Key, identity *sigcrypto.KeyPair) (*Server, error) {
	if key == nil || identity == nil {
		return nil, errors.New("omen: key and identity are required")
	}
	if err := validateNick(config.Nick); err != nil {
		return nil, fmt.Errorf("omen: host %w", err)
	}
	if config.Version == "" || !utf8.ValidString(config.Version) {
		return nil, errors.New("omen: version is required")
	}
	if config.MaxRemoteVoters == 0 {
		config.MaxRemoteVoters = 32
	}
	if config.MaxRemoteVoters < 1 || config.MaxRemoteVoters > 254 {
		return nil, errors.New("omen: max remote voters must be 1..254")
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
		return nil, errors.New("omen: handshake timeout cannot be negative")
	}
	if config.DeliveryTimeout == 0 {
		config.DeliveryTimeout = 5 * time.Second
	}
	if config.DeliveryTimeout < 0 {
		return nil, errors.New("omen: delivery timeout cannot be negative")
	}
	ballot := Ballot{Question: config.Question, Options: append([]string(nil), config.Options...)}
	if err := validateBallot(ballot); err != nil {
		return nil, err
	}
	if config.AllowedPublicKeys != nil {
		if len(config.AllowedPublicKeys) < 2 || len(config.AllowedPublicKeys) > 255 {
			return nil, errors.New("omen: restricted roster must contain 2..255 identities")
		}
		seen := make(map[sigcrypto.PublicKey]struct{}, len(config.AllowedPublicKeys))
		hostFound := false
		for _, public := range config.AllowedPublicKeys {
			if _, duplicate := seen[public]; duplicate {
				return nil, errors.New("omen: restricted roster contains a duplicate identity")
			}
			seen[public] = struct{}{}
			if public == identity.Public() {
				hostFound = true
			}
		}
		if !hostFound {
			return nil, errors.New("omen: host identity is not in restricted roster")
		}
		config.AllowedPublicKeys = append([]sigcrypto.PublicKey(nil), config.AllowedPublicKeys...)
	}
	listener, err := net.Listen("tcp", fmt.Sprintf("127.0.0.1:%d", config.Port))
	if err != nil {
		return nil, err
	}
	server := &Server{
		listener: listener, config: config, key: *key, identity: identity,
		ballot: ballot, phase: PhaseLobby, done: make(chan struct{}),
	}
	if _, err := io.ReadFull(config.Random, server.ballot.SessionID[:]); err != nil {
		listener.Close()
		secretbox.ZeroKey(&server.key)
		return nil, fmt.Errorf("omen: generate session id: %w", err)
	}
	if _, err := EncodeBallot(server.ballot); err != nil {
		listener.Close()
		secretbox.ZeroKey(&server.key)
		return nil, err
	}
	return server, nil
}

func (server *Server) Port() uint16 {
	return uint16(server.listener.Addr().(*net.TCPAddr).Port)
}

func (server *Server) Ready() (connected, keyed int) {
	server.mu.Lock()
	defer server.mu.Unlock()
	for _, voter := range server.voters {
		if voter.hasKey {
			keyed++
		}
	}
	return len(server.voters), keyed
}

// Run serves voters until a verified artifact is complete, Abort is called, or
// ctx is canceled. Start must be called separately once the lobby is ready.
func (server *Server) Run(ctx context.Context) ([]byte, error) {
	started := false
	server.serve.Do(func() {
		started = true
		server.wg.Add(1)
		go server.acceptLoop()
	})
	if !started {
		return nil, errors.New("omen: server Run called more than once")
	}
	stop := context.AfterFunc(ctx, func() { server.fail(ctx.Err()) })
	defer stop()
	select {
	case <-server.done:
	case <-ctx.Done():
		<-server.done
	}
	_ = server.listener.Close()
	server.closeVoters()
	server.wg.Wait()
	secretbox.ZeroKey(&server.key)
	server.zeroBlindings()
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
				server.fail(fmt.Errorf("omen: accept: %w", err))
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
	var voter *remoteVoter
	defer func() {
		_ = connection.Close()
		if admitted {
			server.voterDisconnected(voter)
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
	defer secretbox.Zero(plaintext)
	if join.Type != MessageJoin || len(plaintext) != len(Magic) || subtle.ConstantTimeCompare(plaintext, []byte(Magic)) != 1 {
		return
	}
	if err := validateNick(join.Sender); err != nil {
		return
	}

	server.mu.Lock()
	if server.phase != PhaseLobby || len(server.voters) >= server.config.MaxRemoteVoters {
		server.mu.Unlock()
		return
	}
	resolved, err := server.resolveNickLocked(join.Sender)
	if err != nil {
		server.mu.Unlock()
		return
	}
	voter = &remoteVoter{connection: connection, nick: resolved}
	server.voters = append(server.voters, voter)
	count := len(server.voters) + 1
	server.mu.Unlock()
	admitted = true
	if err := connection.SetReadDeadline(time.Time{}); err != nil {
		return
	}
	ballotPayload, err := EncodeBallot(server.ballot)
	if err != nil || server.sendVoter(voter, MessageBallot, ballotPayload) != nil {
		return
	}
	server.logf("* %s joined (%d voters)\n", voter.nick, count)

	for {
		value, payload, err := readEncrypted(connection, &server.key)
		if err != nil {
			return
		}
		handleErr := server.handleVoterMessage(voter, value.Type, payload)
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

func (server *Server) handleVoterMessage(voter *remoteVoter, messageType byte, payload []byte) error {
	switch messageType {
	case MessagePublicKey:
		if len(payload) != sigcrypto.PublicKeySize {
			return errors.New("omen: invalid public key payload")
		}
		var public sigcrypto.PublicKey
		copy(public[:], payload)
		server.mu.Lock()
		defer server.mu.Unlock()
		if server.phase != PhaseLobby || voter.hasKey || public == server.identity.Public() {
			return errors.New("omen: invalid or duplicate voter identity")
		}
		for _, existing := range server.voters {
			if existing != voter && existing.hasKey && existing.publicKey == public {
				return errors.New("omen: duplicate voter identity")
			}
		}
		if server.config.AllowedPublicKeys != nil && !containsPublicKey(server.config.AllowedPublicKeys, public) {
			return errors.New("omen: voter identity is not in restricted roster")
		}
		voter.publicKey, voter.hasKey = public, true
		return nil

	case MessageCommitment:
		server.mu.Lock()
		if server.phase != PhaseCommit || !voter.hasKey || voter.hasCommit {
			server.mu.Unlock()
			return ErrAborted
		}
		commitment, err := DecodeCommitment(payload, voter.slot)
		if err != nil || !sigcrypto.VerifyOmenCommitment(voter.publicKey, server.rosterHash, commitment.Commitment, commitment.Signature) {
			server.mu.Unlock()
			return ErrAborted
		}
		voter.commitment, voter.hasCommit = commitment, true
		received, total := server.commitmentCountLocked(), len(server.voters)+1
		complete := received == total && !server.advancing
		if complete {
			server.advancing = true
		}
		server.mu.Unlock()
		server.logf("Waiting for commitments... (%d/%d)\n", received, total)
		if complete {
			server.enterRevealPhase()
		}
		return nil

	case MessageReveal:
		server.mu.Lock()
		if server.phase != PhaseReveal || !voter.hasCommit || voter.hasReveal {
			server.mu.Unlock()
			return ErrAborted
		}
		reveal, err := DecodeReveal(payload)
		if err != nil || int(reveal.Vote) >= len(server.ballot.Options) ||
			sigcrypto.MakeCommitment(reveal.Vote, reveal.Blinding) != voter.commitment.Commitment {
			server.mu.Unlock()
			return ErrAborted
		}
		voter.reveal, voter.hasReveal = reveal, true
		received, total := server.revealCountLocked(), len(server.voters)+1
		complete := received == total && !server.advancing
		if complete {
			server.advancing = true
			server.phase = PhaseTally
		}
		server.mu.Unlock()
		server.logf("Waiting for reveals... (%d/%d)\n", received, total)
		if complete {
			server.finishVote()
		}
		return nil

	case MessageLeave:
		return nil
	case MessageAbort:
		return ErrAborted
	default:
		server.mu.Lock()
		phase := server.phase
		server.mu.Unlock()
		if phase == PhaseLobby {
			return errors.New("omen: unexpected lobby message")
		}
		return ErrAborted
	}
}

// Begin freezes the fully keyed lobby roster and starts the commit phase. The
// host then calls Vote, matching the interactive /start followed by number flow.
func (server *Server) Begin() error {
	server.terminalMu.Lock()
	defer server.terminalMu.Unlock()
	select {
	case <-server.done:
		return ErrAborted
	default:
	}
	server.mu.Lock()
	if server.phase != PhaseLobby || len(server.voters) == 0 {
		server.mu.Unlock()
		return ErrNotReady
	}
	for _, voter := range server.voters {
		if !voter.hasKey {
			server.mu.Unlock()
			return ErrNotReady
		}
	}
	roster := make([]Peer, len(server.voters)+1)
	roster[0] = Peer{Slot: 0, Nick: server.config.Nick, PublicKey: server.identity.Public()}
	for index, voter := range server.voters {
		voter.slot = byte(index + 1)
		roster[index+1] = Peer{Slot: voter.slot, Nick: voter.nick, PublicKey: voter.publicKey}
	}
	if err := validatePeers(roster); err != nil {
		server.mu.Unlock()
		return err
	}
	rosterHash, err := rosterHash(roster)
	if err != nil {
		server.mu.Unlock()
		return err
	}
	if size := maximumArtifactSize(server.config.Version, server.ballot, roster, server.config.Now()); size > frame.MaxPayloadLen {
		server.mu.Unlock()
		return fmt.Errorf("omen: final artifact could be %d bytes, exceeding frame limit", size)
	}
	server.roster, server.rosterHash = roster, rosterHash
	server.phase = PhaseCommit
	snapshot := append([]*remoteVoter(nil), server.voters...)
	server.mu.Unlock()
	_ = server.listener.Close()

	peerPayload, err := EncodePeerList(roster)
	if err != nil {
		server.failLocked(err)
		return err
	}
	if err := server.broadcast(snapshot, MessagePeerList, peerPayload); err != nil {
		server.failLocked(err)
		return err
	}
	phasePayload, _ := EncodePhase(PhaseCommit, rosterHash)
	if err := server.broadcast(snapshot, MessagePhase, phasePayload); err != nil {
		server.failLocked(err)
		return err
	}
	server.logf("\n--- Vote started (%d voters) ---\n", len(roster))
	server.logf("Waiting for host vote and commitments... (0/%d)\n", len(roster))
	return nil
}

// Vote seals the host's choice after Begin. It can be called exactly once.
func (server *Server) Vote(vote byte) error {
	server.mu.Lock()
	if server.phase != PhaseCommit || server.hostVoted || int(vote) >= len(server.ballot.Options) {
		server.mu.Unlock()
		return ErrNotReady
	}
	var blinding [32]byte
	if _, err := io.ReadFull(server.config.Random, blinding[:]); err != nil {
		server.mu.Unlock()
		return fmt.Errorf("omen: generate host blinding: %w", err)
	}
	commitmentHash := sigcrypto.MakeCommitment(vote, blinding)
	signature, err := sigcrypto.SignOmenCommitment(server.identity, server.rosterHash, commitmentHash)
	if err != nil {
		server.mu.Unlock()
		return err
	}
	server.hostCommitment = Commitment{Slot: 0, Commitment: commitmentHash, Signature: signature}
	server.hostReveal, server.hostVoted = Reveal{Vote: vote, Blinding: blinding}, true
	received, total := server.commitmentCountLocked(), len(server.voters)+1
	complete := received == total && !server.advancing
	if complete {
		server.advancing = true
	}
	server.mu.Unlock()
	server.logf("Vote sealed. Waiting for commitments... (%d/%d)\n", received, total)
	if complete {
		server.enterRevealPhase()
	}
	return nil
}

// Start is a programmatic convenience for fixed-vote callers.
func (server *Server) Start(vote byte) error {
	if int(vote) >= len(server.ballot.Options) {
		return ErrNotReady
	}
	if err := server.Begin(); err != nil {
		return err
	}
	return server.Vote(vote)
}

func (server *Server) enterRevealPhase() {
	server.terminalMu.Lock()
	defer server.terminalMu.Unlock()
	select {
	case <-server.done:
		return
	default:
	}
	server.mu.Lock()
	if server.phase != PhaseCommit || server.commitmentCountLocked() != len(server.voters)+1 {
		server.advancing = false
		server.mu.Unlock()
		return
	}
	commitments := server.commitmentsLocked()
	snapshot := append([]*remoteVoter(nil), server.voters...)
	roster := append([]Peer(nil), server.roster...)
	rosterHash := server.rosterHash
	server.mu.Unlock()

	setHash := commitSetHash(commitments)
	if err := VerifyCommitSet(commitments, setHash, roster, rosterHash, nil, nil); err != nil {
		server.failLocked(err)
		return
	}
	payload, err := EncodeCommitSet(commitments, setHash)
	if err != nil {
		server.failLocked(err)
		return
	}
	if err := server.broadcast(snapshot, MessageCommitSet, payload); err != nil {
		server.failLocked(err)
		return
	}
	server.mu.Lock()
	if server.phase != PhaseCommit {
		server.mu.Unlock()
		return
	}
	server.phase, server.advancing = PhaseReveal, false
	server.mu.Unlock()
	phasePayload, _ := EncodePhase(PhaseReveal, rosterHash)
	if err := server.broadcast(snapshot, MessagePhase, phasePayload); err != nil {
		server.failLocked(err)
		return
	}
	server.logf("All commitments verified. Reveal phase started.\n")
}

func (server *Server) finishVote() {
	server.mu.Lock()
	if server.phase != PhaseTally || server.revealCountLocked() != len(server.voters)+1 {
		server.mu.Unlock()
		return
	}
	roster := append([]Peer(nil), server.roster...)
	commitments := server.commitmentsLocked()
	reveals := make([]Reveal, 0, len(server.voters)+1)
	reveals = append(reveals, server.hostReveal)
	for _, voter := range server.voters {
		reveals = append(reveals, voter.reveal)
	}
	defer zeroRevealSlice(reveals)
	snapshot := append([]*remoteVoter(nil), server.voters...)
	server.mu.Unlock()

	if err := shuffleReveals(server.config.Random, reveals); err != nil {
		server.fail(err)
		return
	}
	if _, valid := matchReveals(reveals, commitments); !valid {
		server.fail(errors.New("omen: internal reveal bijection failed"))
		return
	}
	counts := ComputeTally(reveals, len(server.ballot.Options))
	artifact, err := BuildArtifact(Artifact{
		Version: server.config.Version, SessionID: server.ballot.SessionID,
		Timestamp: uint64(server.config.Now().Unix()), Question: server.ballot.Question,
		Options: append([]string(nil), server.ballot.Options...), VoterCount: len(roster),
		RosterHash: server.rosterHash, Roster: roster, Commitments: commitments,
		Reveals: reveals, Counts: counts, Winner: ComputeWinner(server.ballot.Options, counts),
	}, server.identity)
	if err != nil {
		server.fail(err)
		return
	}
	revealPayload, err := EncodeRevealSet(reveals)
	if err != nil {
		server.fail(err)
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
	if err := server.broadcast(snapshot, MessageRevealSet, revealPayload); err != nil {
		server.complete(nil, fmt.Errorf("omen: deliver reveal set: %w", err))
		return
	}
	if err := server.broadcast(snapshot, MessageTally, artifact); err != nil {
		server.complete(nil, fmt.Errorf("omen: deliver final artifact: %w", err))
		return
	}
	server.logf("\nVote complete. %d verified ballots.\n", len(reveals))
	server.complete(artifact, nil)
}

func (server *Server) commitmentCountLocked() int {
	count := 0
	if server.hostVoted {
		count++
	}
	for _, voter := range server.voters {
		if voter.hasCommit {
			count++
		}
	}
	return count
}

func (server *Server) revealCountLocked() int {
	count := 0
	if server.hostVoted {
		count++
	}
	for _, voter := range server.voters {
		if voter.hasReveal {
			count++
		}
	}
	return count
}

func (server *Server) commitmentsLocked() []Commitment {
	commitments := make([]Commitment, len(server.voters)+1)
	commitments[0] = server.hostCommitment
	for index, voter := range server.voters {
		commitments[index+1] = voter.commitment
	}
	return commitments
}

func (server *Server) broadcast(voters []*remoteVoter, messageType byte, payload []byte) error {
	errorsFound := make(chan error, len(voters))
	var group sync.WaitGroup
	for _, voter := range voters {
		group.Add(1)
		go func(voter *remoteVoter) {
			defer group.Done()
			if err := server.sendVoter(voter, messageType, payload); err != nil {
				errorsFound <- err
			}
		}(voter)
	}
	group.Wait()
	close(errorsFound)
	for err := range errorsFound {
		return err
	}
	return nil
}

func (server *Server) sendVoter(voter *remoteVoter, messageType byte, payload []byte) error {
	return server.sendVoterWithTimeout(voter, messageType, payload, server.config.DeliveryTimeout)
}

func (server *Server) sendVoterWithTimeout(voter *remoteVoter, messageType byte, payload []byte, timeout time.Duration) error {
	voter.writeMu.Lock()
	defer voter.writeMu.Unlock()
	if timeout > 0 {
		_ = voter.connection.SetWriteDeadline(time.Now().Add(timeout))
		defer voter.connection.SetWriteDeadline(time.Time{})
	}
	return sendEncrypted(voter.connection, nil, &server.key, messageType, "system", payload, server.config.Now())
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
	server.phase = PhaseDone
	snapshot := append([]*remoteVoter(nil), server.voters...)
	server.mu.Unlock()
	_ = server.listener.Close()
	var group sync.WaitGroup
	for _, voter := range snapshot {
		group.Add(1)
		go func(voter *remoteVoter) {
			defer group.Done()
			_ = server.sendVoterWithTimeout(voter, MessageAbort, []byte("aborted"), 250*time.Millisecond)
		}(voter)
	}
	group.Wait()
	server.complete(nil, err)
}

func (server *Server) complete(artifact []byte, err error) {
	server.doneOnce.Do(func() {
		server.resultMu.Lock()
		server.result = voteResult{artifact: append([]byte(nil), artifact...), err: err}
		server.resultMu.Unlock()
		close(server.done)
	})
}

func (server *Server) voterDisconnected(voter *remoteVoter) {
	server.mu.Lock()
	phase := server.phase
	if phase == PhaseLobby {
		for index, candidate := range server.voters {
			if candidate == voter {
				server.voters = append(server.voters[:index], server.voters[index+1:]...)
				break
			}
		}
		count := len(server.voters) + 1
		server.mu.Unlock()
		server.logf("* %s left (%d voters)\n", voter.nick, count)
		return
	}
	server.mu.Unlock()
	if phase != PhaseDone {
		server.fail(ErrAborted)
	}
}

func (server *Server) resolveNickLocked(input string) (string, error) {
	used := func(candidate string) bool {
		if candidate == server.config.Nick {
			return true
		}
		for _, voter := range server.voters {
			if candidate == voter.nick {
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
	return "", errors.New("omen: too many nick collisions")
}

func validateNick(value string) error {
	if value == "" || len(value) > frame.MaxSenderLen || !utf8.ValidString(value) {
		return fmt.Errorf("nick must be non-empty valid UTF-8 and at most %d bytes", frame.MaxSenderLen)
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

func containsPublicKey(keys []sigcrypto.PublicKey, target sigcrypto.PublicKey) bool {
	for _, key := range keys {
		if key == target {
			return true
		}
	}
	return false
}

func shuffleReveals(random io.Reader, reveals []Reveal) error {
	for index := len(reveals) - 1; index > 0; index-- {
		chosen, err := rand.Int(random, big.NewInt(int64(index+1)))
		if err != nil {
			return fmt.Errorf("omen: shuffle reveals: %w", err)
		}
		other := int(chosen.Int64())
		reveals[index], reveals[other] = reveals[other], reveals[index]
	}
	return nil
}

func (server *Server) closeVoters() {
	server.mu.Lock()
	snapshot := append([]*remoteVoter(nil), server.voters...)
	server.mu.Unlock()
	for _, voter := range snapshot {
		_ = voter.connection.Close()
	}
}

func (server *Server) zeroBlindings() {
	server.mu.Lock()
	defer server.mu.Unlock()
	secretbox.Zero(server.hostReveal.Blinding[:])
	for _, voter := range server.voters {
		secretbox.Zero(voter.reveal.Blinding[:])
	}
}

func zeroRevealSlice(reveals []Reveal) {
	for index := range reveals {
		secretbox.Zero(reveals[index].Blinding[:])
	}
}

func (server *Server) logf(format string, args ...any) {
	server.logMu.Lock()
	defer server.logMu.Unlock()
	fmt.Fprintf(server.config.Logger, format, args...)
}

func maximumArtifactSize(version string, ballot Ballot, roster []Peer, now time.Time) int {
	length := len(`{"omen_version":"`) + escapedLength(version) +
		len(`","session_id":"`) + 64 + len(`","timestamp":`) + len(strconv.FormatUint(uint64(now.Unix()), 10)) +
		len(`,"question":"`) + escapedLength(ballot.Question) + len(`","options":[`)
	maxWinner := 0
	for index, option := range ballot.Options {
		if index > 0 {
			length++
		}
		escaped := escapedLength(option)
		length += 2 + escaped
		if escaped > maxWinner {
			maxWinner = escaped
		}
	}
	length += len(`],"voter_count":`) + len(strconv.Itoa(len(roster))) + len(`,"roster_hash":"`) + 64 + len(`","roster":[`)
	for index, peer := range roster {
		if index > 0 {
			length++
		}
		length += len(`{"slot":`) + len(strconv.Itoa(int(peer.Slot))) + len(`,"nick":"`) + escapedLength(peer.Nick) + len(`","pubkey":"`) + 64 + len(`"}`)
	}
	length += len(`],"commitments":[`)
	for index := range roster {
		if index > 0 {
			length++
		}
		length += len(`{"slot":`) + len(strconv.Itoa(index)) + len(`,"commitment":"`) + 64 + len(`","signature":"`) + 128 + len(`"}`)
	}
	length += len(`],"reveals":[`)
	for index := range roster {
		if index > 0 {
			length++
		}
		length += len(`{"vote":`) + 3 + len(`,"blinding":"`) + 64 + len(`"}`)
	}
	length += len(`],"tally":{`)
	for index, option := range ballot.Options {
		if index > 0 {
			length++
		}
		length += 2 + escapedLength(option) + 1 + 3
	}
	return length + len(`},"winner":"`) + maxWinner + len(`","host_pubkey":"`) + 64 + len(`","host_signature":"`) + 128 + len(`"}`)
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
