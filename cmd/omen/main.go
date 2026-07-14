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
	omenapp "github.com/no-way-labs/cauldron/internal/omen"
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
		fmt.Fprintf(os.Stderr, "omen %s\n", version)
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
	default:
		fmt.Fprintf(os.Stderr, "Unknown command: %s\n", args[0])
		printUsage()
		return 1
	}
}

type hostOptions struct {
	question                 string
	optionText               string
	port, borePort           uint16
	localOnly                bool
	password, nick           string
	identity, output, roster string
	passwordSet, nickSet     bool
	identitySet, outputSet   bool
	rosterSet, optionTextSet bool
	maxRemote                int
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
		"--roster": {TakesValue: true, Apply: func(value string) error {
			options.roster, options.rosterSet = value, true
			return nil
		}},
		"--options": {TakesValue: true, Apply: func(value string) error {
			options.optionText, options.optionTextSet = value, true
			return nil
		}},
		"--max-voters": {TakesValue: true, Apply: func(value string) error {
			parsed, err := strconv.ParseUint(value, 10, 8)
			if err != nil || parsed < 1 || parsed > 254 {
				return errors.New("must be between 1 and 254 (the host occupies one roster slot)")
			}
			options.maxRemote = int(parsed)
			return nil
		}},
	}
	if err := cli.Parse(args, flags, func(value string) error {
		if options.question != "" {
			return fmt.Errorf("unexpected argument %s", value)
		}
		if value == "" {
			return errors.New("question cannot be empty")
		}
		options.question = value
		return nil
	}); err != nil {
		fmt.Fprintf(os.Stderr, "Error: %v\n", err)
		return 1
	}
	if options.question == "" {
		fmt.Fprintln(os.Stderr, "Error: question is required")
		fmt.Fprintln(os.Stderr, "Usage: omen host \"Your question?\" [--options a,b,c]")
		return 1
	}
	ballotOptions, err := parseOptions(options.optionTextSet, options.optionText)
	if err != nil {
		fmt.Fprintf(os.Stderr, "Error: %v\n", err)
		return 1
	}
	identityPhrase, identityFound, err := cli.ResolveSecret(options.identitySet, options.identity, "OMEN_IDENTITY")
	if err != nil {
		fmt.Fprintf(os.Stderr, "Error: %v\n", err)
		return 1
	}
	defer secretbox.Zero(identityPhrase)
	if options.rosterSet && !identityFound {
		fmt.Fprintln(os.Stderr, "Error: --identity or OMEN_IDENTITY is required when using --roster")
		return 1
	}
	var identity sigcrypto.KeyPair
	if identityFound {
		identity, err = sigcrypto.DeriveIdentity(identityPhrase)
	} else {
		identity, err = sigcrypto.GenerateIdentity()
	}
	if err != nil {
		fmt.Fprintf(os.Stderr, "Fatal: identity setup failed: %v\n", err)
		return 1
	}
	defer identity.Zero()
	var allowed []sigcrypto.PublicKey
	var covenantGroup string
	if options.rosterSet {
		allowed, covenantGroup, err = loadCovenantRoster(options.roster)
		if err != nil {
			fmt.Fprintf(os.Stderr, "Error: cannot load roster %s: %v\n", options.roster, err)
			return 1
		}
	}
	password, found, err := cli.ResolveSecret(options.passwordSet, options.password, "OMEN_PASSWORD")
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
	key, err := secretbox.Derive(password, secretbox.OmenSalt)
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
	server, err := omenapp.NewServer(omenapp.ServerConfig{
		Port: options.port, MaxRemoteVoters: options.maxRemote, Nick: nick,
		Question: options.question, Options: ballotOptions, Version: version,
		AllowedPublicKeys: allowed, Logger: os.Stderr,
	}, &key, &identity)
	if err != nil {
		fmt.Fprintf(os.Stderr, "Fatal: could not host vote: %v\n", err)
		return 1
	}
	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer stop()

	printBanner(version)
	printBallot(options.question, ballotOptions)
	public := identity.Public()
	fmt.Fprintf(os.Stderr, "\x1b[38;5;245mIdentity:\x1b[0m %x...\n", public[:4])
	if options.rosterSet {
		fmt.Fprintf(os.Stderr, "\x1b[38;5;245mRoster:\x1b[0m %s (%d eligible members; group metadata: %s)\n", options.roster, len(allowed), covenantGroup)
	}
	fmt.Fprintf(os.Stderr, "\x1b[38;5;245mPassword:\x1b[0m %s\n", password)
	fmt.Fprintf(os.Stderr, "\x1b[38;5;245mNick:\x1b[0m %s\n", nick)
	fmt.Fprintf(os.Stderr, "\x1b[38;5;245mLocal:\x1b[0m localhost:%d\n", server.Port())

	activeTunnel := establishTunnel(ctx, server.Port(), options.borePort, options.localOnly)
	if activeTunnel != nil {
		defer activeTunnel.Close()
	}
	fmt.Fprintln(os.Stderr, "\n\x1b[38;5;245mTo join:\x1b[0m")
	if activeTunnel != nil {
		info := activeTunnel.Info()
		fmt.Fprintf(os.Stderr, "  \x1b[38;5;240momen join %s:%d --password %s\x1b[0m\n\n", info.PublicHost, info.PublicPort, password)
	} else {
		fmt.Fprintf(os.Stderr, "  \x1b[38;5;240momen join localhost:%d --password %s\x1b[0m\n\n", server.Port(), password)
	}
	fmt.Fprintln(os.Stderr, "Waiting for voters... (/start to begin, /abort to cancel)")

	type result struct {
		artifact []byte
		err      error
	}
	done := make(chan result, 1)
	go func() {
		artifact, runErr := server.Run(ctx)
		done <- result{artifact, runErr}
	}()
	commands := boundedLines(os.Stdin, 4096)
	awaitingVote := false
	for {
		select {
		case finished := <-done:
			if finished.err != nil {
				if errors.Is(finished.err, context.Canceled) || errors.Is(finished.err, omenapp.ErrAborted) {
					fmt.Fprintln(os.Stderr, "Vote aborted.")
					return 1
				}
				fmt.Fprintf(os.Stderr, "Vote failed: %v\n", finished.err)
				return 1
			}
			if err := emitArtifact(finished.artifact, options.outputSet, options.output); err != nil {
				fmt.Fprintf(os.Stderr, "Error: %v\n", err)
				return 1
			}
			fmt.Fprintln(os.Stderr, "\nVote complete.")
			return 0

		case command, open := <-commands:
			if !open {
				commands = nil
				continue
			}
			trimmed := strings.TrimSpace(command)
			if trimmed == "/abort" {
				server.Abort()
				continue
			}
			if !awaitingVote {
				if trimmed != "/start" {
					continue
				}
				if err := server.Begin(); err != nil {
					if errors.Is(err, omenapp.ErrNotReady) {
						connected, keyed := server.Ready()
						if connected == 0 {
							fmt.Fprintln(os.Stderr, "\x1b[38;5;196mError: Need at least one other voter to start.\x1b[0m")
						} else {
							fmt.Fprintf(os.Stderr, "\x1b[38;5;196mError: Not all voters have exchanged keys yet. (%d/%d ready)\x1b[0m\n", keyed, connected)
						}
					} else {
						fmt.Fprintf(os.Stderr, "Error: %v\n", err)
					}
					continue
				}
				awaitingVote = true
				printVotePrompt(ballotOptions)
				continue
			}
			choice, err := parseChoice(trimmed, len(ballotOptions))
			if err != nil {
				fmt.Fprintln(os.Stderr, "\x1b[38;5;196mError: Invalid choice.\x1b[0m")
				printVotePrompt(ballotOptions)
				continue
			}
			if err := server.Vote(choice); err != nil {
				fmt.Fprintf(os.Stderr, "Error: %v\n", err)
				server.Abort()
				continue
			}
			awaitingVote = false
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
		fmt.Fprintln(os.Stderr, "Usage: omen join <host:port> --password <pass>")
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
	password, found, err := cli.ResolveSecret(options.passwordSet, options.password, "OMEN_PASSWORD")
	if err != nil || !found {
		fmt.Fprintln(os.Stderr, "Error: --password or OMEN_PASSWORD is required")
		return 1
	}
	defer secretbox.Zero(password)
	identityPhrase, identityFound, err := cli.ResolveSecret(options.identitySet, options.identity, "OMEN_IDENTITY")
	if err != nil {
		fmt.Fprintf(os.Stderr, "Error: %v\n", err)
		return 1
	}
	defer secretbox.Zero(identityPhrase)
	key, err := secretbox.Derive(password, secretbox.OmenSalt)
	if err != nil {
		fmt.Fprintf(os.Stderr, "Fatal: key derivation failed: %v\n", err)
		return 1
	}
	defer secretbox.ZeroKey(&key)
	var identity sigcrypto.KeyPair
	if identityFound {
		identity, err = sigcrypto.DeriveIdentity(identityPhrase)
	} else {
		identity, err = sigcrypto.GenerateIdentity()
	}
	if err != nil {
		fmt.Fprintf(os.Stderr, "Fatal: identity setup failed: %v\n", err)
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
	fmt.Fprintf(os.Stderr, "\x1b[38;5;245mConnected as:\x1b[0m %s\n", nick)
	fmt.Fprintf(os.Stderr, "\x1b[38;5;245mIdentity:\x1b[0m %x...\n", public[:4])
	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer stop()
	input := bufio.NewReaderSize(os.Stdin, 256)
	client, err := omenapp.Connect(ctx, omenapp.ClientConfig{
		Address: host + ":" + strconv.Itoa(int(port)), Nick: nick,
		Timeout: options.timeout, TimeoutSet: true, Logger: os.Stderr,
		Vote: func(ballot omenapp.Ballot) (byte, error) {
			printVotePrompt(ballot.Options)
			line, readErr := readBoundedLineContext(ctx, input, 64)
			if readErr != nil {
				return 0, readErr
			}
			return parseChoice(strings.TrimSpace(line), len(ballot.Options))
		},
	}, &key, &identity)
	if err != nil {
		fmt.Fprintf(os.Stderr, "Failed to join vote: %v\n", err)
		return 2
	}
	artifact, err := client.Run(ctx)
	if err != nil {
		fmt.Fprintf(os.Stderr, "Vote failed: %v\n", err)
		return 1
	}
	if err := emitArtifact(artifact, options.outputSet, options.output); err != nil {
		fmt.Fprintf(os.Stderr, "Error: %v\n", err)
		return 1
	}
	fmt.Fprintln(os.Stderr, "\nVote complete.")
	return 0
}

func runVerify(args []string) int {
	if len(args) != 1 {
		fmt.Fprintln(os.Stderr, "Usage: omen verify <artifact.json>")
		return 1
	}
	data, err := readArtifact(args[0], omenapp.MaxArtifactBytes)
	if err != nil {
		fmt.Fprintf(os.Stderr, "Error: cannot read %s: %v\n", args[0], err)
		return 1
	}
	result, err := omenapp.VerifyArtifact(data)
	if err != nil {
		fmt.Fprintf(os.Stderr, "\x1b[38;5;196mVerification FAILED: %v\x1b[0m\n", err)
		return 1
	}
	fmt.Fprintln(os.Stderr, "\n\x1b[38;5;214mOmen Artifact Verification\x1b[0m")
	fmt.Fprintf(os.Stderr, "\n\x1b[38;5;245mFile:\x1b[0m     %s\n", args[0])
	fmt.Fprintf(os.Stderr, "\x1b[38;5;245mQuestion:\x1b[0m %s\n", result.Question)
	fmt.Fprintf(os.Stderr, "\x1b[38;5;245mVoters:\x1b[0m   %d\n", result.VoterCount)
	fmt.Fprintf(os.Stderr, "\x1b[38;5;245mHost key:\x1b[0m  %x\n\n", result.HostPublicKey)
	printCheck("Host signature", result.HostSignatureValid)
	printCheck("Roster hash", result.RosterHashValid)
	printCheck("Commitment signatures", result.CommitmentSignaturesValid)
	printCheck("One canonical commitment per roster member", result.RosterComplete)
	printCheck("Reveal bijection", result.BijectionValid)
	printCheck("Tally recomputation", result.TallyMatches)
	printCheck("Winner matches tally", result.WinnerValid)
	fmt.Fprintln(os.Stderr, "\n\x1b[38;5;245mTally:\x1b[0m")
	for index, option := range result.Options {
		fmt.Fprintf(os.Stderr, "  %s: %d\n", option, result.Counts[index])
	}
	if result.Winner != "" {
		fmt.Fprintf(os.Stderr, "\x1b[38;5;245mWinner:\x1b[0m %s\n", result.Winner)
	}
	if !result.Valid {
		fmt.Fprintln(os.Stderr, "\n\x1b[38;5;196mVerification FAILED — artifact is tampered or inconsistent.\x1b[0m")
		return 1
	}
	fmt.Fprintln(os.Stderr, "\n\x1b[38;5;82mArtifact is authentic and internally consistent.\x1b[0m")
	fmt.Fprintln(os.Stderr, "\x1b[38;5;240mScope: the host signed this record and every recorded commitment has a roster signature.")
	fmt.Fprintln(os.Stderr, "The host can relabel the v1 ballot when re-signing; the artifact does not prove --roster use")
	fmt.Fprintln(os.Stderr, "or real-world voter eligibility. Reveal preimages also map directly back to roster slots, so v1")
	fmt.Fprintln(os.Stderr, "does not provide ballot anonymity against anyone holding this artifact.\x1b[0m")
	return 0
}

func loadCovenantRoster(path string) ([]sigcrypto.PublicKey, string, error) {
	data, err := readArtifact(path, covenantapp.MaxArtifactBytes)
	if err != nil {
		return nil, "", err
	}
	result, err := covenantapp.VerifyArtifact(data)
	if err != nil || !result.Valid {
		if err == nil {
			err = errors.New("covenant signatures are invalid")
		}
		return nil, "", fmt.Errorf("invalid covenant: %w", err)
	}
	keys := make([]sigcrypto.PublicKey, len(result.Members))
	seen := make(map[sigcrypto.PublicKey]struct{}, len(result.Members))
	for index, member := range result.Members {
		if _, duplicate := seen[member.PublicKey]; duplicate {
			return nil, "", errors.New("invalid covenant: duplicate member identity")
		}
		seen[member.PublicKey] = struct{}{}
		keys[index] = member.PublicKey
	}
	return keys, result.GroupName, nil
}

func parseOptions(set bool, value string) ([]string, error) {
	if !set {
		return []string{"yes", "no"}, nil
	}
	var result []string
	for _, item := range strings.Split(value, ",") {
		if trimmed := strings.TrimSpace(item); trimmed != "" {
			result = append(result, trimmed)
		}
	}
	if len(result) < 2 {
		return nil, errors.New("need at least 2 options")
	}
	if len(result) > 255 {
		return nil, errors.New("cannot have more than 255 options")
	}
	seen := make(map[string]struct{}, len(result))
	for _, option := range result {
		if _, duplicate := seen[option]; duplicate {
			return nil, fmt.Errorf("duplicate option %q", option)
		}
		seen[option] = struct{}{}
	}
	return result, nil
}

func parseChoice(value string, optionCount int) (byte, error) {
	choice, err := strconv.ParseUint(value, 10, 8)
	if err != nil || choice < 1 || choice > uint64(optionCount) {
		return 0, errors.New("invalid choice")
	}
	return byte(choice - 1), nil
}

func establishTunnel(ctx context.Context, localPort, borePort uint16, localOnly bool) *tunnel.Tunnel {
	if localOnly {
		return nil
	}
	active, err := tunnel.Establish(ctx, localPort, borePort, tunnel.Config{Logger: os.Stderr})
	if errors.Is(err, tunnel.ErrPortInUse) && borePort > 0 {
		fmt.Fprintf(os.Stderr, "Bore port %d in use, trying random...\n", borePort)
		active, err = tunnel.Establish(ctx, localPort, 0, tunnel.Config{Logger: os.Stderr})
	}
	if err != nil {
		fmt.Fprintf(os.Stderr, "\x1b[38;5;240mWarning: tunnel failed (%v), local only.\x1b[0m\n", err)
		return nil
	}
	active.StartMonitor()
	info := active.Info()
	fmt.Fprintf(os.Stderr, "\x1b[38;5;245mPublic:\x1b[0m %s:%d", info.PublicHost, info.PublicPort)
	if info.RequestedPort > 0 && info.RequestedPort != info.PublicPort {
		fmt.Fprintf(os.Stderr, " (requested %d but unavailable)", info.RequestedPort)
	}
	fmt.Fprintln(os.Stderr)
	return active
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
	withNewline := append(append([]byte(nil), artifact...), '\n')
	if outputSet {
		if err := os.WriteFile(output, withNewline, 0o600); err != nil {
			return fmt.Errorf("cannot write %s: %w", output, err)
		}
		fmt.Fprintf(os.Stderr, "\x1b[38;5;245mArtifact saved to:\x1b[0m %s\n", output)
		return nil
	}
	_, err := os.Stdout.Write(withNewline)
	return err
}

func readArtifact(path string, maximum int) ([]byte, error) {
	file, err := os.Open(path)
	if err != nil {
		return nil, err
	}
	defer file.Close()
	data, err := io.ReadAll(io.LimitReader(file, int64(maximum)+1))
	if err != nil {
		return nil, err
	}
	if len(data) > maximum {
		return nil, errors.New("artifact exceeds size limit")
	}
	return data, nil
}

func boundedLines(reader io.Reader, maximum int) <-chan string {
	lines := make(chan string)
	go func() {
		defer close(lines)
		buffered := bufio.NewReaderSize(reader, min(maximum, 4096))
		for {
			line, err := readBoundedLine(buffered, maximum)
			if line != "" && !errors.Is(err, errLineTooLong) {
				lines <- line
			}
			if err != nil && !errors.Is(err, errLineTooLong) {
				return
			}
		}
	}()
	return lines
}

var errLineTooLong = errors.New("line is too long")

func readBoundedLine(reader *bufio.Reader, maximum int) (string, error) {
	line := make([]byte, 0, min(maximum, 4096))
	overlong := false
	for {
		fragment, err := reader.ReadSlice('\n')
		if !overlong {
			if len(line)+len(fragment) > maximum {
				overlong = true
				line = line[:0]
			} else {
				line = append(line, fragment...)
			}
		}
		if errors.Is(err, bufio.ErrBufferFull) {
			continue
		}
		if overlong {
			return "", errLineTooLong
		}
		return string(line), err
	}
}

func readBoundedLineContext(ctx context.Context, reader *bufio.Reader, maximum int) (string, error) {
	type result struct {
		line string
		err  error
	}
	done := make(chan result, 1)
	go func() {
		line, err := readBoundedLine(reader, maximum)
		done <- result{line: line, err: err}
	}()
	select {
	case <-ctx.Done():
		return "", ctx.Err()
	case value := <-done:
		return value.line, value.err
	}
}

func printCheck(label string, valid bool) {
	mark := "\x1b[38;5;196m✗\x1b[0m"
	if valid {
		mark = "\x1b[38;5;82m✓\x1b[0m"
	}
	fmt.Fprintf(os.Stderr, "  %s %s\n", mark, label)
}

func printBallot(question string, options []string) {
	fmt.Fprintf(os.Stderr, "\x1b[38;5;245mQuestion:\x1b[0m %s\n", question)
	fmt.Fprint(os.Stderr, "\x1b[38;5;245mOptions:\x1b[0m  ")
	for index, option := range options {
		if index > 0 {
			fmt.Fprint(os.Stderr, "  ")
		}
		fmt.Fprintf(os.Stderr, "\x1b[38;5;214m[%d]\x1b[0m %s", index+1, option)
	}
	fmt.Fprintln(os.Stderr)
}

func printVotePrompt(options []string) {
	fmt.Fprint(os.Stderr, "\nSelect: ")
	for index, option := range options {
		if index > 0 {
			fmt.Fprint(os.Stderr, "  ")
		}
		fmt.Fprintf(os.Stderr, "\x1b[38;5;214m[%d]\x1b[0m %s", index+1, option)
	}
	fmt.Fprint(os.Stderr, "\nYour choice: ")
}

func printBanner(value string) {
	fmt.Fprintln(os.Stderr, "\n\x1b[38;5;202m                ·  \x1b[38;5;214m✦\x1b[38;5;202m  ·\x1b[0m")
	fmt.Fprintln(os.Stderr, "\n\x1b[38;5;166m          ╔═╗ ╔╗╔ ╔═╗ ╔╗╔\x1b[0m")
	fmt.Fprintln(os.Stderr, "\x1b[38;5;208m          ║ ║ ║╚╝║ ║╣  ║║║\x1b[0m")
	fmt.Fprintln(os.Stderr, "\x1b[38;5;214m          ╚═╝ ╩  ╩ ╚═╝ ╝╚╝\x1b[0m")
	fmt.Fprintln(os.Stderr, "\x1b[38;5;245m\n       encrypted verifiable vote\x1b[0m")
	fmt.Fprintf(os.Stderr, "\x1b[38;5;240m                v%s\x1b[0m\n", value)
	fmt.Fprintln(os.Stderr, "\n\x1b[38;5;202m                ·  \x1b[38;5;214m✧\x1b[38;5;202m  ·\x1b[0m")
	fmt.Fprintln(os.Stderr)
}

func printUsage() {
	fmt.Fprint(os.Stderr, `Usage: omen <command> [options]

Commands:
  host <question>       Host a vote
  join <host:port>      Join a vote
  verify <file.json>    Verify a vote artifact

Host options:
  --options <a,b,c>      Comma-separated options (default: yes,no)
  --output <file>        Save artifact to file (default: stdout)
  --port <port>          Local port (default: auto)
  --bore-port <port>     Request specific bore port
  --local                Skip tunnel, local only
  --password <pass>      Room password (default: auto-generated)
  --nick <name>          Your display name (default: auto-generated)
  --max-voters <n>       Max remote voters (default: 32; range: 1-254)
  --roster <file.json>   Restrict to a strictly verified covenant
  --identity <phrase>    Identity passphrase (required with --roster)

Join options:
  --password <pass>      Room password (required)
  --nick <name>          Your display name (default: auto-generated)
  --output <file>        Save artifact to file (default: stdout)
  --timeout <secs>       Connect/initial-write timeout (default: 30)
  --identity <phrase>    Identity passphrase (required for restricted votes)
`)
}
