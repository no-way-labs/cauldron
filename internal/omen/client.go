package omen

import (
	"context"
	"crypto/rand"
	"errors"
	"fmt"
	"io"
	"net"
	"sync"
	"time"

	"github.com/no-way-labs/cauldron/internal/secretbox"
	"github.com/no-way-labs/cauldron/internal/sigcrypto"
)

type VoteFunc func(Ballot) (byte, error)

type ClientConfig struct {
	Address    string
	Nick       string
	Timeout    time.Duration
	TimeoutSet bool
	Now        func() time.Time
	Random     io.Reader
	Logger     io.Writer
	Vote       VoteFunc
}

type Client struct {
	connection net.Conn
	key        secretbox.Key
	identity   *sigcrypto.KeyPair
	config     ClientConfig
	writeMu    sync.Mutex
	closeOnce  sync.Once

	phase         byte
	ballot        *Ballot
	roster        []Peer
	rosterHash    sigcrypto.Hash
	ownSlot       byte
	hasOwnSlot    bool
	vote          byte
	blinding      [32]byte
	ownCommitment sigcrypto.Hash
	voted         bool
	commitments   []Commitment
	reveals       []Reveal
}

func Connect(ctx context.Context, config ClientConfig, key *secretbox.Key, identity *sigcrypto.KeyPair) (*Client, error) {
	if key == nil || identity == nil {
		return nil, errors.New("omen: key and identity are required")
	}
	if err := validateNick(config.Nick); err != nil {
		return nil, err
	}
	if config.Address == "" {
		return nil, errors.New("omen: address is required")
	}
	if config.Vote == nil {
		return nil, errors.New("omen: vote callback is required")
	}
	if !config.TimeoutSet {
		config.Timeout = 30 * time.Second
	}
	if config.Timeout < 0 {
		return nil, errors.New("omen: timeout cannot be negative")
	}
	if config.Now == nil {
		config.Now = time.Now
	}
	if config.Random == nil {
		config.Random = rand.Reader
	}
	if config.Logger == nil {
		config.Logger = io.Discard
	}
	dialer := net.Dialer{Timeout: config.Timeout}
	connection, err := dialer.DialContext(ctx, "tcp", config.Address)
	if err != nil {
		return nil, err
	}
	client := &Client{
		connection: connection, key: *key, identity: identity, config: config,
		phase: PhaseLobby,
	}
	if config.Timeout > 0 {
		if err := connection.SetDeadline(time.Now().Add(config.Timeout)); err != nil {
			connection.Close()
			secretbox.ZeroKey(&client.key)
			return nil, err
		}
	}
	if err := sendEncrypted(connection, &client.writeMu, &client.key, MessageJoin, config.Nick, []byte(Magic), config.Now()); err != nil {
		connection.Close()
		secretbox.ZeroKey(&client.key)
		return nil, err
	}
	public := identity.Public()
	if err := sendEncrypted(connection, &client.writeMu, &client.key, MessagePublicKey, config.Nick, public[:], config.Now()); err != nil {
		connection.Close()
		secretbox.ZeroKey(&client.key)
		return nil, err
	}
	if err := connection.SetDeadline(time.Time{}); err != nil {
		connection.Close()
		secretbox.ZeroKey(&client.key)
		return nil, err
	}
	return client, nil
}

// Run returns only an artifact that passes strict verification and matches the
// ballot, roster, commitment set, and reveal set this client observed live.
func (client *Client) Run(ctx context.Context) ([]byte, error) {
	connection := client.connection
	stop := context.AfterFunc(ctx, func() { _ = connection.Close() })
	defer stop()
	defer client.Close()
	for {
		value, payload, err := readEncrypted(connection, &client.key)
		if err != nil {
			if ctx.Err() != nil {
				return nil, ctx.Err()
			}
			return nil, fmt.Errorf("omen: vote ended before a verified artifact: %w", err)
		}
		var artifact []byte
		handleErr := func() error {
			defer secretbox.Zero(payload)
			switch value.Type {
			case MessageBallot:
				if client.ballot != nil || client.phase != PhaseLobby {
					return errors.New("omen: ballot arrived out of order")
				}
				ballot, err := DecodeBallot(payload)
				if err != nil {
					return err
				}
				client.ballot = &ballot
				fmt.Fprintf(client.config.Logger, "Question: %s\n", ballot.Question)
				for index, option := range ballot.Options {
					fmt.Fprintf(client.config.Logger, "  %d. %s\n", index+1, option)
				}
				fmt.Fprintln(client.config.Logger, "Waiting for host to start...")
				return nil

			case MessagePeerList:
				if client.ballot == nil || client.roster != nil || client.phase != PhaseLobby {
					return errors.New("omen: peer list arrived out of order")
				}
				roster, err := DecodePeerList(payload)
				if err != nil {
					return err
				}
				own := client.identity.Public()
				ownCount := 0
				for _, peer := range roster {
					if peer.PublicKey == own {
						client.ownSlot, client.hasOwnSlot = peer.Slot, true
						ownCount++
					}
				}
				if ownCount != 1 {
					return errors.New("omen: own identity is not exactly once in peer list")
				}
				hash, err := rosterHash(roster)
				if err != nil {
					return err
				}
				client.roster, client.rosterHash = roster, hash
				return nil

			case MessagePhase:
				phase, receivedHash, err := DecodePhase(payload)
				if err != nil {
					return err
				}
				if client.roster == nil || receivedHash != client.rosterHash {
					return errors.New("omen: roster hash mismatch")
				}
				switch phase {
				case PhaseCommit:
					if client.phase != PhaseLobby || client.ballot == nil || client.voted {
						return errors.New("omen: invalid commit phase transition")
					}
					vote, err := client.config.Vote(cloneBallot(*client.ballot))
					if err != nil {
						return fmt.Errorf("omen: choose vote: %w", err)
					}
					if int(vote) >= len(client.ballot.Options) {
						return errors.New("omen: selected vote is outside ballot")
					}
					if _, err := io.ReadFull(client.config.Random, client.blinding[:]); err != nil {
						return fmt.Errorf("omen: generate blinding: %w", err)
					}
					client.vote = vote
					client.ownCommitment = sigcrypto.MakeCommitment(vote, client.blinding)
					signature, err := sigcrypto.SignOmenCommitment(client.identity, client.rosterHash, client.ownCommitment)
					if err != nil {
						return err
					}
					commitment := Commitment{Slot: client.ownSlot, Commitment: client.ownCommitment, Signature: signature}
					if err := sendEncrypted(connection, &client.writeMu, &client.key, MessageCommitment, client.config.Nick, EncodeCommitment(commitment), client.config.Now()); err != nil {
						return err
					}
					client.phase, client.voted = PhaseCommit, true
					fmt.Fprintln(client.config.Logger, "Vote sealed. Waiting for all commitments...")
					return nil

				case PhaseReveal:
					if client.phase != PhaseCommit || client.commitments == nil || !client.voted {
						return errors.New("omen: reveal phase arrived before a verified commitment set")
					}
					reveal := Reveal{Vote: client.vote, Blinding: client.blinding}
					if err := sendEncrypted(connection, &client.writeMu, &client.key, MessageReveal, client.config.Nick, EncodeReveal(reveal), client.config.Now()); err != nil {
						return err
					}
					client.phase = PhaseReveal
					fmt.Fprintln(client.config.Logger, "Reveal sent. Waiting for results...")
					return nil
				default:
					return errors.New("omen: unexpected phase transition")
				}

			case MessageCommitSet:
				if client.phase != PhaseCommit || !client.voted || client.commitments != nil || !client.hasOwnSlot {
					return errors.New("omen: commitment set arrived out of order")
				}
				commitments, setHash, err := DecodeCommitSet(payload)
				if err != nil {
					return err
				}
				if err := VerifyCommitSet(commitments, setHash, client.roster, client.rosterHash, &client.ownSlot, &client.ownCommitment); err != nil {
					return err
				}
				client.commitments = commitments
				fmt.Fprintln(client.config.Logger, "Commitment set verified.")
				return nil

			case MessageRevealSet:
				if client.phase != PhaseReveal || client.commitments == nil || client.reveals != nil {
					return errors.New("omen: reveal set arrived out of order")
				}
				reveals, err := DecodeRevealSet(payload)
				if err != nil {
					return err
				}
				for _, reveal := range reveals {
					if int(reveal.Vote) >= len(client.ballot.Options) {
						return errors.New("omen: reveal contains invalid vote index")
					}
				}
				if _, valid := matchReveals(reveals, client.commitments); !valid {
					return errors.New("omen: reveal set does not form a commitment bijection")
				}
				client.reveals = reveals
				counts := ComputeTally(reveals, len(client.ballot.Options))
				fmt.Fprintf(client.config.Logger, "Results (%d verified votes):\n", len(reveals))
				for index, option := range client.ballot.Options {
					fmt.Fprintf(client.config.Logger, "  %s: %d\n", option, counts[index])
				}
				return nil

			case MessageTally:
				if client.phase != PhaseReveal || client.reveals == nil || client.commitments == nil {
					return errors.New("omen: final artifact arrived before verified reveals")
				}
				result, err := VerifyArtifact(payload)
				if err != nil {
					return err
				}
				if !result.Valid {
					return errors.New("omen: final artifact is invalid")
				}
				if err := client.bindFinal(result); err != nil {
					return err
				}
				client.phase = PhaseDone
				artifact = append([]byte(nil), payload...)
				return nil

			case MessageAbort:
				return ErrAborted
			default:
				return errors.New("omen: unexpected host message")
			}
		}()
		if handleErr != nil {
			return nil, handleErr
		}
		if artifact != nil {
			return artifact, nil
		}
	}
}

func (client *Client) bindFinal(result VerifyResult) error {
	if client.ballot == nil || result.SessionID != client.ballot.SessionID || result.Question != client.ballot.Question ||
		!equalStrings(result.Options, client.ballot.Options) || result.RosterHash != client.rosterHash ||
		!equalPeerLists(result.Roster, client.roster) || !equalCommitments(result.Commitments, client.commitments) ||
		!equalReveals(result.Reveals, client.reveals) {
		return errors.New("omen: final artifact does not match observed vote")
	}
	if !client.hasOwnSlot || int(client.ownSlot) >= len(result.Commitments) ||
		result.Commitments[client.ownSlot].Commitment != client.ownCommitment ||
		result.Roster[client.ownSlot].PublicKey != client.identity.Public() {
		return errors.New("omen: final artifact omits or modifies own vote")
	}
	if result.HostPublicKey != client.roster[0].PublicKey {
		return errors.New("omen: final artifact changes host identity")
	}
	counts := ComputeTally(client.reveals, len(client.ballot.Options))
	if !equalCounts(counts, result.Counts) || result.Winner != ComputeWinner(client.ballot.Options, counts) {
		return errors.New("omen: final artifact changes observed tally")
	}
	return nil
}

func (client *Client) Close() error {
	var err error
	client.closeOnce.Do(func() {
		if client.connection != nil {
			err = client.connection.Close()
			client.connection = nil
		}
		secretbox.ZeroKey(&client.key)
		secretbox.Zero(client.blinding[:])
	})
	return err
}

func cloneBallot(ballot Ballot) Ballot {
	ballot.Options = append([]string(nil), ballot.Options...)
	return ballot
}

func equalStrings(first, second []string) bool {
	if len(first) != len(second) {
		return false
	}
	for index := range first {
		if first[index] != second[index] {
			return false
		}
	}
	return true
}

func equalCommitments(first, second []Commitment) bool {
	if len(first) != len(second) {
		return false
	}
	for index := range first {
		if first[index] != second[index] {
			return false
		}
	}
	return true
}

func equalReveals(first, second []Reveal) bool {
	if len(first) != len(second) {
		return false
	}
	for index := range first {
		if first[index] != second[index] {
			return false
		}
	}
	return true
}
