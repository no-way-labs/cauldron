package main

import (
	"bufio"
	"context"
	"errors"
	"fmt"
	"io"
	"math"
	"os"
	"os/signal"
	"strconv"
	"strings"
	"syscall"
	"time"

	"github.com/no-way-labs/cauldron/internal/cli"
	covenantapp "github.com/no-way-labs/cauldron/internal/covenant"
	"github.com/no-way-labs/cauldron/internal/ident"
	"github.com/no-way-labs/cauldron/internal/secretbox"
	"github.com/no-way-labs/cauldron/internal/sigcrypto"
	"github.com/no-way-labs/cauldron/internal/tunnel"
)

var version = "0.0.0-dev"

func main() { os.Exit(run(os.Args[1:])) }

func run(args []string) int {
	if len(args) == 0 {
		printUsage()
		return 0
	}
	switch args[0] {
	case "--version", "-v":
		fmt.Fprintf(os.Stderr, "covenant %s\n", version)
		return 0
	case "--help", "-h":
		printUsage()
		return 0
	case "host":
		return runHost(args[1:])
	case "join":
		return runJoin(args[1:])
	case "verify":
		return runVerify(args[1:])
	case "members":
		return runMembers(args[1:])
	default:
		fmt.Fprintf(os.Stderr, "Unknown command: %s\n", args[0])
		printUsage()
		return 1
	}
}

type hostOptions struct {
	groupName              string
	port, borePort         uint16
	localOnly              bool
	password, nick         string
	identity, output       string
	passwordSet, nickSet   bool
	identitySet, outputSet bool
	maxRemote              int
}

func runHost(args []string) int {
	options := hostOptions{maxRemote: 32}
	flags := map[string]cli.Option{
		"--port": {TakesValue: true, Apply: func(value string) error {
			parsed, err := cli.Uint16(value)
			options.port = parsed
			return err
		}},
		"--bore-port": {TakesValue: true, Apply: func(value string) error {
			parsed, err := cli.Uint16(value)
			options.borePort = parsed
			return err
		}},
		"--local": {Apply: func(string) error { options.localOnly = true; return nil }},
		"--password": {TakesValue: true, Apply: func(value string) error {
			options.password, options.passwordSet = value, true
			return nil
		}},
		"--nick": {TakesValue: true, Apply: func(value string) error {
			options.nick, options.nickSet = value, true
			return nil
		}},
		"--identity": {TakesValue: true, Apply: func(value string) error {
			options.identity, options.identitySet = value, true
			return nil
		}},
		"--output": {TakesValue: true, Apply: func(value string) error {
			options.output, options.outputSet = value, true
			return nil
		}},
		"--max-members": {TakesValue: true, Apply: func(value string) error {
			parsed, err := strconv.ParseUint(value, 10, 8)
			if err != nil || parsed < 1 || parsed > 254 {
				return errors.New("must be between 1 and 254 (the host occupies one roster slot)")
			}
			options.maxRemote = int(parsed)
			return nil
		}},
	}
	if err := cli.Parse(args, flags, func(value string) error {
		if options.groupName != "" {
			return fmt.Errorf("unexpected argument %s", value)
		}
		if value == "" {
			return errors.New("group name cannot be empty")
		}
		options.groupName = value
		return nil
	}); err != nil {
		fmt.Fprintf(os.Stderr, "Error: %v\n", err)
		return 1
	}
	if options.groupName == "" {
		fmt.Fprintln(os.Stderr, "Error: group name is required")
		fmt.Fprintln(os.Stderr, "Usage: covenant host \"Group Name\" --identity \"my passphrase\"")
		return 1
	}
	identityPhrase, found, err := cli.ResolveSecret(options.identitySet, options.identity, "COVENANT_IDENTITY")
	if err != nil || !found {
		fmt.Fprintln(os.Stderr, "Error: --identity or COVENANT_IDENTITY is required")
		return 1
	}
	defer secretbox.Zero(identityPhrase)
	identity, err := sigcrypto.DeriveIdentity(identityPhrase)
	if err != nil {
		fmt.Fprintf(os.Stderr, "Fatal: identity derivation failed: %v\n", err)
		return 1
	}
	defer identity.Zero()
	password, found, err := cli.ResolveSecret(options.passwordSet, options.password, "COVENANT_PASSWORD")
	if err != nil {
		fmt.Fprintf(os.Stderr, "Error: %v\n", err)
		return 1
	}
	if !found {
		password, err = ident.Generate()
		if err != nil {
			fmt.Fprintf(os.Stderr, "Fatal: password generation failed: %v\n", err)
			return 1
		}
	}
	defer secretbox.Zero(password)
	key, err := secretbox.Derive(password, secretbox.CovenantSalt)
	if err != nil {
		fmt.Fprintf(os.Stderr, "Fatal: key derivation failed: %v\n", err)
		return 1
	}
	defer secretbox.ZeroKey(&key)
	nick, err := resolvedNick(options.nickSet, options.nick)
	if err != nil {
		fmt.Fprintf(os.Stderr, "Error: %v\n", err)
		return 1
	}
	server, err := covenantapp.NewServer(covenantapp.ServerConfig{
		Port: options.port, MaxRemoteMembers: options.maxRemote,
		Nick: nick, GroupName: options.groupName, Version: version, Logger: os.Stderr,
	}, &key, &identity)
	if err != nil {
		fmt.Fprintf(os.Stderr, "Fatal: could not host ceremony: %v\n", err)
		return 1
	}
	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer stop()

	printBanner(version)
	fmt.Fprintf(os.Stderr, "\x1b[38;5;245mGroup:\x1b[0m    %s\n", options.groupName)
	public := identity.Public()
	fmt.Fprintf(os.Stderr, "\x1b[38;5;245mIdentity:\x1b[0m %x...\n", public[:4])
	fmt.Fprintf(os.Stderr, "\x1b[38;5;245mPassword:\x1b[0m %s\n", password)
	fmt.Fprintf(os.Stderr, "\x1b[38;5;245mNick:\x1b[0m %s\n", nick)
	fmt.Fprintf(os.Stderr, "\x1b[38;5;245mLocal:\x1b[0m localhost:%d\n", server.Port())

	var activeTunnel *tunnel.Tunnel
	if !options.localOnly {
		activeTunnel, err = tunnel.Establish(ctx, server.Port(), options.borePort, tunnel.Config{Logger: os.Stderr})
		if errors.Is(err, tunnel.ErrPortInUse) && options.borePort > 0 {
			fmt.Fprintf(os.Stderr, "Bore port %d in use, trying random...\n", options.borePort)
			activeTunnel, err = tunnel.Establish(ctx, server.Port(), 0, tunnel.Config{Logger: os.Stderr})
		}
		if err != nil {
			fmt.Fprintf(os.Stderr, "\x1b[38;5;240mWarning: tunnel failed (%v), local only.\x1b[0m\n", err)
			activeTunnel = nil
		} else {
			activeTunnel.StartMonitor()
			defer activeTunnel.Close()
			info := activeTunnel.Info()
			fmt.Fprintf(os.Stderr, "\x1b[38;5;245mPublic:\x1b[0m %s:%d", info.PublicHost, info.PublicPort)
			if info.RequestedPort > 0 && info.RequestedPort != info.PublicPort {
				fmt.Fprintf(os.Stderr, " (requested %d but unavailable)", info.RequestedPort)
			}
			fmt.Fprintln(os.Stderr)
		}
	}
	fmt.Fprintln(os.Stderr, "\n\x1b[38;5;245mTo join:\x1b[0m")
	if activeTunnel != nil {
		info := activeTunnel.Info()
		fmt.Fprintf(os.Stderr, "  \x1b[38;5;240mcovenant join %s:%d --password %s --identity \"<passphrase>\"\x1b[0m\n\n", info.PublicHost, info.PublicPort, password)
	} else {
		fmt.Fprintf(os.Stderr, "  \x1b[38;5;240mcovenant join localhost:%d --password %s --identity \"<passphrase>\"\x1b[0m\n\n", server.Port(), password)
	}
	fmt.Fprintln(os.Stderr, "Waiting for members... (/seal to sign, /abort to cancel)")

	type result struct {
		artifact []byte
		err      error
	}
	done := make(chan result, 1)
	go func() {
		artifact, err := server.Run(ctx)
		done <- result{artifact, err}
	}()
	commands := boundedLines(os.Stdin, 4096)
	for {
		select {
		case finished := <-done:
			if finished.err != nil {
				if errors.Is(finished.err, context.Canceled) || errors.Is(finished.err, covenantapp.ErrAborted) {
					fmt.Fprintln(os.Stderr, "Ceremony aborted.")
					return 1
				}
				fmt.Fprintf(os.Stderr, "Ceremony failed: %v\n", finished.err)
				return 1
			}
			if err := emitArtifact(finished.artifact, options.outputSet, options.output); err != nil {
				fmt.Fprintf(os.Stderr, "Error: %v\n", err)
				return 1
			}
			fmt.Fprintln(os.Stderr, "\nCeremony complete.")
			return 0
		case command, open := <-commands:
			if !open {
				commands = nil
				continue
			}
			switch strings.TrimSpace(command) {
			case "/seal":
				if err := server.Seal(); err != nil {
					if errors.Is(err, covenantapp.ErrNotReady) {
						connected, keyed := server.Ready()
						if connected == 0 {
							fmt.Fprintln(os.Stderr, "Error: Need at least one other member to seal.")
						} else {
							fmt.Fprintf(os.Stderr, "Error: Not all members have exchanged keys yet. (%d/%d ready)\n", keyed, connected)
						}
					} else {
						fmt.Fprintf(os.Stderr, "Error: %v\n", err)
					}
				}
			case "/abort":
				server.Abort()
			}
		}
	}
}

type joinOptions struct {
	positionals              []string
	password, identity       string
	nick, output             string
	passwordSet, identitySet bool
	nickSet, outputSet       bool
	timeout                  time.Duration
}

func runJoin(args []string) int {
	if len(args) == 0 {
		fmt.Fprintln(os.Stderr, "Usage: covenant join <host:port> --password <pass> --identity \"<passphrase>\"")
		return 1
	}
	options := joinOptions{timeout: 30 * time.Second}
	flags := map[string]cli.Option{
		"--password": {TakesValue: true, Apply: func(value string) error { options.password, options.passwordSet = value, true; return nil }},
		"--identity": {TakesValue: true, Apply: func(value string) error { options.identity, options.identitySet = value, true; return nil }},
		"--nick":     {TakesValue: true, Apply: func(value string) error { options.nick, options.nickSet = value, true; return nil }},
		"--output":   {TakesValue: true, Apply: func(value string) error { options.output, options.outputSet = value, true; return nil }},
		"--timeout": {TakesValue: true, Apply: func(value string) error {
			seconds, err := cli.Uint64(value)
			if err != nil || seconds > uint64(math.MaxInt64/int64(time.Second)) {
				return errors.New("must be a non-negative duration in seconds")
			}
			options.timeout = time.Duration(seconds) * time.Second
			return nil
		}},
	}
	if err := cli.Parse(args, flags, func(value string) error {
		if len(options.positionals) > 0 {
			return fmt.Errorf("unexpected argument %s", value)
		}
		options.positionals = append(options.positionals, value)
		return nil
	}); err != nil {
		fmt.Fprintf(os.Stderr, "Error: %v\n", err)
		return 1
	}
	if len(options.positionals) != 1 {
		fmt.Fprintln(os.Stderr, "Error: target is required")
		return 1
	}
	host, port, err := cli.SplitTargetLast(options.positionals[0])
	if err != nil {
		fmt.Fprintln(os.Stderr, "Error: target must be host:port")
		return 1
	}
	password, found, err := cli.ResolveSecret(options.passwordSet, options.password, "COVENANT_PASSWORD")
	if err != nil || !found {
		fmt.Fprintln(os.Stderr, "Error: --password or COVENANT_PASSWORD is required")
		return 1
	}
	defer secretbox.Zero(password)
	identityPhrase, found, err := cli.ResolveSecret(options.identitySet, options.identity, "COVENANT_IDENTITY")
	if err != nil || !found {
		fmt.Fprintln(os.Stderr, "Error: --identity or COVENANT_IDENTITY is required")
		return 1
	}
	defer secretbox.Zero(identityPhrase)
	key, err := secretbox.Derive(password, secretbox.CovenantSalt)
	if err != nil {
		fmt.Fprintf(os.Stderr, "Fatal: key derivation failed: %v\n", err)
		return 1
	}
	defer secretbox.ZeroKey(&key)
	identity, err := sigcrypto.DeriveIdentity(identityPhrase)
	if err != nil {
		fmt.Fprintf(os.Stderr, "Fatal: identity derivation failed: %v\n", err)
		return 1
	}
	defer identity.Zero()
	nick, err := resolvedNick(options.nickSet, options.nick)
	if err != nil {
		fmt.Fprintf(os.Stderr, "Error: %v\n", err)
		return 1
	}
	printBanner(version)
	public := identity.Public()
	fmt.Fprintf(os.Stderr, "\x1b[38;5;245mIdentity:\x1b[0m %x...\n", public[:4])
	fmt.Fprintf(os.Stderr, "\x1b[38;5;245mNick:\x1b[0m %s\n", nick)
	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer stop()
	client, err := covenantapp.Connect(ctx, covenantapp.ClientConfig{
		Address: host + ":" + strconv.Itoa(int(port)), Nick: nick,
		Timeout: options.timeout, TimeoutSet: true, Logger: os.Stderr,
	}, &key, &identity)
	if err != nil {
		fmt.Fprintf(os.Stderr, "Failed to join ceremony: %v\n", err)
		return 2
	}
	artifact, err := client.Run(ctx)
	if err != nil {
		fmt.Fprintf(os.Stderr, "Ceremony failed: %v\n", err)
		return 1
	}
	if err := emitArtifact(artifact, options.outputSet, options.output); err != nil {
		fmt.Fprintf(os.Stderr, "Error: %v\n", err)
		return 1
	}
	fmt.Fprintln(os.Stderr, "\nCeremony complete.")
	return 0
}

func runVerify(args []string) int {
	if len(args) != 1 {
		fmt.Fprintln(os.Stderr, "Usage: covenant verify <artifact.json>")
		return 1
	}
	data, err := readArtifact(args[0])
	if err != nil {
		fmt.Fprintf(os.Stderr, "Error: cannot read %s: %v\n", args[0], err)
		return 1
	}
	result, err := covenantapp.VerifyArtifact(data)
	if err != nil {
		fmt.Fprintf(os.Stderr, "\x1b[38;5;196mVerification FAILED: %v\x1b[0m\n", err)
		return 1
	}
	fmt.Fprintln(os.Stderr, "\n\x1b[38;5;45mCovenant Verification\x1b[0m")
	fmt.Fprintf(os.Stderr, "\n\x1b[38;5;245mFile:\x1b[0m      %s\n", args[0])
	fmt.Fprintf(os.Stderr, "\x1b[38;5;245mGroup:\x1b[0m     %s  \x1b[38;5;240m(unauthenticated metadata)\x1b[0m\n", result.GroupName)
	fmt.Fprintf(os.Stderr, "\x1b[38;5;245mMembers:\x1b[0m   %d\n", result.MemberCount)
	for _, member := range result.Members {
		mark := "\x1b[38;5;196m✗\x1b[0m"
		if member.Valid {
			mark = "\x1b[38;5;82m✓\x1b[0m"
		}
		fmt.Fprintf(os.Stderr, "  %s %s  \x1b[38;5;240m%x...\x1b[0m\n", mark, member.Nick, member.PublicKey[:4])
	}
	if !result.Valid {
		fmt.Fprintln(os.Stderr, "\n\x1b[38;5;196mSome signatures INVALID.\x1b[0m")
		return 1
	}
	fmt.Fprintln(os.Stderr, "\n\x1b[38;5;82mAll roster signatures valid.\x1b[0m")
	fmt.Fprintln(os.Stderr, "\x1b[38;5;240mGroup, timestamp, session id, and version are not signed in covenant v1.\x1b[0m")
	return 0
}

func runMembers(args []string) int {
	if len(args) != 1 {
		fmt.Fprintln(os.Stderr, "Usage: covenant members <artifact.json>")
		return 1
	}
	data, err := readArtifact(args[0])
	if err != nil {
		fmt.Fprintf(os.Stderr, "Error: cannot read %s: %v\n", args[0], err)
		return 1
	}
	result, err := covenantapp.VerifyArtifact(data)
	if err != nil || !result.Valid {
		fmt.Fprintf(os.Stderr, "Error: covenant is not valid: %v\n", err)
		return 1
	}
	fmt.Fprintf(os.Stderr, "\n\x1b[38;5;45m%s\x1b[0m  (%d members)\n\n", result.GroupName, result.MemberCount)
	for _, member := range result.Members {
		fmt.Fprintf(os.Stderr, "  %s  \x1b[38;5;240m%x\x1b[0m\n", member.Nick, member.PublicKey)
	}
	fmt.Fprintln(os.Stderr)
	return 0
}

func resolvedNick(set bool, value string) (string, error) {
	if set {
		if value == "" {
			return "", errors.New("nick cannot be empty")
		}
		return value, nil
	}
	generated, err := ident.Generate()
	return string(generated), err
}

func emitArtifact(artifact []byte, outputSet bool, output string) error {
	if outputSet {
		if err := os.WriteFile(output, append(append([]byte(nil), artifact...), '\n'), 0o600); err != nil {
			return fmt.Errorf("cannot write %s: %w", output, err)
		}
		fmt.Fprintf(os.Stderr, "\x1b[38;5;245mCovenant saved to:\x1b[0m %s\n", output)
		return nil
	}
	_, err := os.Stdout.Write(append(append([]byte(nil), artifact...), '\n'))
	return err
}

func readArtifact(path string) ([]byte, error) {
	file, err := os.Open(path)
	if err != nil {
		return nil, err
	}
	defer file.Close()
	data, err := io.ReadAll(io.LimitReader(file, covenantapp.MaxArtifactBytes+1))
	if err != nil {
		return nil, err
	}
	if len(data) > covenantapp.MaxArtifactBytes {
		return nil, errors.New("artifact exceeds 1 MiB")
	}
	return data, nil
}

func boundedLines(reader io.Reader, max int) <-chan string {
	lines := make(chan string)
	go func() {
		defer close(lines)
		buffered := bufio.NewReaderSize(reader, min(max, 4096))
		line := make([]byte, 0, min(max, 4096))
		overlong := false
		for {
			fragment, err := buffered.ReadSlice('\n')
			if !overlong {
				if len(line)+len(fragment) > max {
					overlong = true
					line = line[:0]
				} else {
					line = append(line, fragment...)
				}
			}
			if errors.Is(err, bufio.ErrBufferFull) {
				continue
			}
			if !overlong && len(line) > 0 {
				lines <- string(line)
			}
			line = line[:0]
			overlong = false
			if err != nil {
				return
			}
		}
	}()
	return lines
}

func printBanner(value string) {
	fmt.Fprintln(os.Stderr, "\n\x1b[38;5;33m                ·  \x1b[38;5;45m✦\x1b[38;5;33m  ·\x1b[0m")
	fmt.Fprintln(os.Stderr, "\n\x1b[38;5;39m    ╔═╗ ╔═╗ ╦  ╦ ╔═╗ ╔╗╔ ╔═╗ ╔╗╔ ╔╦╗\x1b[0m")
	fmt.Fprintln(os.Stderr, "\x1b[38;5;45m    ║   ║ ║ ╚╗╔╝ ║╣  ║║║ ╠═╣ ║║║  ║\x1b[0m")
	fmt.Fprintln(os.Stderr, "\x1b[38;5;51m    ╚═╝ ╚═╝  ╚╝  ╚═╝ ╝╚╝ ╩ ╩ ╝╚╝  ╩\x1b[0m")
	fmt.Fprintln(os.Stderr, "\x1b[38;5;245m\n     membership signing ceremony\x1b[0m")
	fmt.Fprintf(os.Stderr, "\x1b[38;5;240m                v%s\x1b[0m\n", value)
	fmt.Fprintln(os.Stderr, "\n\x1b[38;5;33m                ·  \x1b[38;5;45m✧\x1b[38;5;33m  ·\x1b[0m")
	fmt.Fprintln(os.Stderr)
}

func printUsage() {
	fmt.Fprint(os.Stderr, `Usage: covenant <command> [options]

Commands:
  host <group-name>     Host a signing ceremony
  join <host:port>      Join a signing ceremony
  verify <file.json>    Verify a covenant artifact
  members <file.json>   List members in a covenant

Host options:
  --identity <phrase>    Identity passphrase (required)
  --output <file>        Save artifact to file (default: stdout)
  --port <port>          Local port (default: auto)
  --bore-port <port>     Request specific bore port
  --local                Skip tunnel, local only
  --password <pass>      Room password (default: auto-generated)
  --nick <name>          Your display name (default: auto-generated)
  --max-members <n>      Max participants (default: 32)

Join options:
  --password <pass>      Room password (required)
  --identity <phrase>    Identity passphrase (required)
  --nick <name>          Your display name (default: auto-generated)
  --output <file>        Save artifact to file (default: stdout)
  --timeout <secs>       Connection timeout (default: 30)

`)
}
