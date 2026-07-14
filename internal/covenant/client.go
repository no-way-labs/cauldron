package covenant

import (
	"context"
	"errors"
	"fmt"
	"io"
	"net"
	"sync"
	"time"
	"unicode/utf8"

	"github.com/no-way-labs/cauldron/internal/secretbox"
	"github.com/no-way-labs/cauldron/internal/sigcrypto"
)

type ClientConfig struct {
	Address    string
	Nick       string
	Timeout    time.Duration
	TimeoutSet bool
	Now        func() time.Time
	Logger     io.Writer
}

type Client struct {
	connection net.Conn
	key        secretbox.Key
	identity   *sigcrypto.KeyPair
	config     ClientConfig
	writeMu    sync.Mutex
	closeOnce  sync.Once

	groupName  string
	roster     []Member
	rosterHash sigcrypto.Hash
	signed     bool
}

func Connect(ctx context.Context, config ClientConfig, key *secretbox.Key, identity *sigcrypto.KeyPair) (*Client, error) {
	if key == nil || identity == nil {
		return nil, errors.New("covenant: key and identity are required")
	}
	if err := validateNick(config.Nick); err != nil {
		return nil, err
	}
	if config.Address == "" {
		return nil, errors.New("covenant: address is required")
	}
	if !config.TimeoutSet {
		config.Timeout = 30 * time.Second
	}
	if config.Timeout < 0 {
		return nil, errors.New("covenant: timeout cannot be negative")
	}
	if config.Now == nil {
		config.Now = time.Now
	}
	if config.Logger == nil {
		config.Logger = io.Discard
	}
	dialer := net.Dialer{Timeout: config.Timeout}
	connection, err := dialer.DialContext(ctx, "tcp", config.Address)
	if err != nil {
		return nil, err
	}
	client := &Client{connection: connection, key: *key, identity: identity, config: config}
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

func (client *Client) Run(ctx context.Context) ([]byte, error) {
	connection := client.connection
	stop := context.AfterFunc(ctx, func() { connection.Close() })
	defer stop()
	defer client.Close()
	for {
		value, payload, err := readEncrypted(client.connection, &client.key)
		if err != nil {
			if ctx.Err() != nil {
				return nil, ctx.Err()
			}
			return nil, fmt.Errorf("covenant: ceremony ended before a verified artifact: %w", err)
		}
		var artifact []byte
		handleErr := func() error {
			defer secretbox.Zero(payload)
			switch value.Type {
			case MessagePhase:
				if client.groupName == "" && client.roster == nil {
					if len(payload) == 0 || !utf8.Valid(payload) {
						return errors.New("covenant: invalid group name")
					}
					client.groupName = string(payload)
					fmt.Fprintf(client.config.Logger, "Group:    %s\n", client.groupName)
					fmt.Fprintln(client.config.Logger, "Waiting for host to seal...")
					return nil
				}
				phase, err := DecodePhase(payload)
				if err != nil {
					return err
				}
				if phase != PhaseSeal || client.roster == nil || client.signed {
					return errors.New("covenant: invalid phase transition")
				}
				fmt.Fprintln(client.config.Logger, "Signing roster...")
				signature, err := sigcrypto.SignCovenantRoster(client.identity, client.rosterHash)
				if err != nil {
					return err
				}
				if err := sendEncrypted(client.connection, &client.writeMu, &client.key, MessageSignature, client.config.Nick, signature[:], client.config.Now()); err != nil {
					return err
				}
				client.signed = true
				fmt.Fprintln(client.config.Logger, "Signature sent. Waiting for all signatures...")
				return nil
			case MessageRoster:
				if client.groupName == "" || client.roster != nil {
					return errors.New("covenant: roster arrived out of order")
				}
				members, err := DecodeRoster(payload)
				if err != nil {
					return err
				}
				own := client.identity.Public()
				ownCount := 0
				hashInput := make([]sigcrypto.CovenantMember, len(members))
				for index, member := range members {
					hashInput[index] = sigcrypto.CovenantMember{Nick: member.Nick, PublicKey: member.PublicKey}
					if member.PublicKey == own {
						ownCount++
					}
				}
				if ownCount != 1 {
					return errors.New("covenant: own identity is not exactly once in roster")
				}
				hash, _, err := sigcrypto.CovenantRosterHash(hashInput)
				if err != nil {
					return err
				}
				client.roster, client.rosterHash = members, hash
				fmt.Fprintf(client.config.Logger, "\nRoster (%d members):\n", len(members))
				for _, member := range members {
					fmt.Fprintf(client.config.Logger, "  * %s  %x...\n", member.Nick, member.PublicKey[:4])
				}
				return nil
			case MessageCovenant:
				if !client.signed || client.roster == nil {
					return errors.New("covenant: final artifact arrived before signing")
				}
				result, err := VerifyArtifact(payload)
				if err != nil {
					return err
				}
				if !result.Valid {
					return errors.New("covenant: final artifact has invalid signatures")
				}
				if err := client.bindFinal(result); err != nil {
					return err
				}
				artifact = append([]byte(nil), payload...)
				fmt.Fprintf(client.config.Logger, "\n  COVENANT SEALED  %d members signed\n\n", len(result.Members))
				return nil
			case MessageAbort:
				return ErrAborted
			default:
				return errors.New("covenant: unexpected host message")
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
	if result.GroupName != client.groupName || result.RosterHash != client.rosterHash || len(result.Members) != len(client.roster) {
		return errors.New("covenant: final artifact does not match observed ceremony")
	}
	own := client.identity.Public()
	foundOwn := false
	for index, member := range result.Members {
		observed := client.roster[index]
		if member.Nick != observed.Nick || member.PublicKey != observed.PublicKey || !member.Valid {
			return errors.New("covenant: final artifact roster differs from observed roster")
		}
		if member.PublicKey == own {
			foundOwn = true
		}
	}
	if !foundOwn {
		return errors.New("covenant: final artifact omits own identity")
	}
	return nil
}

func (client *Client) Close() error {
	var err error
	client.closeOnce.Do(func() {
		if client.connection != nil {
			err = client.connection.Close()
		}
		secretbox.ZeroKey(&client.key)
	})
	return err
}
