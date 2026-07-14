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
	"github.com/no-way-labs/cauldron/internal/familiarcore"
	"github.com/no-way-labs/cauldron/internal/ident"
	seanceapp "github.com/no-way-labs/cauldron/internal/seance"
	"github.com/no-way-labs/cauldron/internal/secretbox"
	"github.com/no-way-labs/cauldron/internal/tunnel"
	"golang.org/x/term"
)

var version = "0.0.0-dev"

var errQuit = errors.New("seance: user quit")

func main() { os.Exit(run(os.Args[1:])) }

func run(args []string) int {
	if len(args) == 0 {
		printUsage()
		return 0
	}
	switch args[0] {
	case "--version", "-v":
		fmt.Fprintf(os.Stderr, "seance %s\n", version)
		return 0
	case "host":
		return runHost(args[1:])
	case "join":
		return runJoin(args[1:])
	default:
		fmt.Fprintf(os.Stderr, "Unknown command: %s\n", args[0])
		printUsage()
		return 1
	}
}

type hostOptions struct {
	port, borePort       uint16
	localOnly            bool
	password, nick       string
	passwordSet, nickSet bool
	maxPeers             int
}

func runHost(args []string) int {
	options := hostOptions{maxPeers: 8}
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
		"--max-peers": {TakesValue: true, Apply: func(value string) error {
			parsed, err := strconv.ParseUint(value, 10, 8)
			if err != nil || parsed < 1 || parsed > 255 {
				return errors.New("must be between 1 and 255")
			}
			options.maxPeers = int(parsed)
			return nil
		}},
	}
	if err := cli.Parse(args, flags, func(value string) error { return fmt.Errorf("unexpected argument %s", value) }); err != nil {
		fmt.Fprintf(os.Stderr, "Error: %v\n", err)
		return 1
	}
	password, found, err := cli.ResolveSecret(options.passwordSet, options.password, "SEANCE_PASSWORD")
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
	key, err := secretbox.Derive(password, secretbox.SeanceSalt)
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
	ui := newTerminalUI(os.Stderr)
	server, err := seanceapp.NewServer(seanceapp.ServerConfig{
		Port: options.port, MaxPeers: options.maxPeers, Nick: nick, OnEvent: ui.event, Logger: os.Stderr,
	}, &key)
	if err != nil {
		fmt.Fprintf(os.Stderr, "Fatal: could not host room: %v\n", err)
		return 1
	}
	ctx, cancel := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer cancel()

	printBanner()
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
		printJoinCommands(info.PublicHost, info.PublicPort, string(password))
	} else {
		printJoinCommands("localhost", server.Port(), string(password))
	}
	fmt.Fprint(os.Stderr, "\x1b[38;5;245mWaiting for participants...\x1b[38;5;240m (type /quit to exit)\x1b[0m\n\n")

	done := make(chan error, 1)
	go func() { done <- server.Run(ctx) }()
	serviceDone, loopErr := runInteractive(ctx, ui, done, false, server.SendMessage)
	if !serviceDone {
		cancel()
		_ = server.Close()
		<-done
	}
	if loopErr != nil && !errors.Is(loopErr, errQuit) && !errors.Is(loopErr, context.Canceled) {
		fmt.Fprintf(os.Stderr, "Room failed: %v\n", loopErr)
		return 1
	}
	return 0
}

type joinOptions struct {
	target               string
	password, nick       string
	passwordSet, nickSet bool
	timeout              time.Duration
	bot, familiar        bool
	apiPort              uint16
}

func runJoin(args []string) int {
	if len(args) == 0 {
		fmt.Fprintln(os.Stderr, "Usage: seance join <host:port> --password <pass>")
		return 1
	}
	options := joinOptions{timeout: 30 * time.Second, apiPort: 9999}
	flags := map[string]cli.Option{
		"--password": {TakesValue: true, Apply: func(value string) error { options.password, options.passwordSet = value, true; return nil }},
		"--nick":     {TakesValue: true, Apply: func(value string) error { options.nick, options.nickSet = value, true; return nil }},
		"--timeout": {TakesValue: true, Apply: func(value string) error {
			seconds, err := cli.Uint64(value)
			if err != nil || seconds > uint64(math.MaxInt64/int64(time.Second)) {
				return errors.New("must be a non-negative duration in seconds")
			}
			options.timeout = time.Duration(seconds) * time.Second
			return nil
		}},
		"--bot":      {Apply: func(string) error { options.bot = true; return nil }},
		"--familiar": {Apply: func(string) error { options.bot, options.familiar = true, true; return nil }},
		"--api-port": {TakesValue: true, Apply: func(value string) error {
			parsed, err := cli.PositiveUint16(value)
			options.apiPort = parsed
			return err
		}},
	}
	if err := cli.Parse(args, flags, func(value string) error {
		if options.target != "" {
			return fmt.Errorf("unexpected argument %s", value)
		}
		options.target = value
		return nil
	}); err != nil {
		fmt.Fprintf(os.Stderr, "Error: %v\n", err)
		return 1
	}
	if options.target == "" {
		fmt.Fprintln(os.Stderr, "Error: target is required")
		return 1
	}
	host, port, err := cli.SplitTargetLast(options.target)
	if err != nil {
		fmt.Fprintln(os.Stderr, "Error: target must be host:port")
		return 1
	}
	password, found, err := cli.ResolveSecret(options.passwordSet, options.password, "SEANCE_PASSWORD")
	if err != nil || !found {
		fmt.Fprintln(os.Stderr, "Error: --password or SEANCE_PASSWORD is required")
		return 1
	}
	defer secretbox.Zero(password)
	key, err := secretbox.Derive(password, secretbox.SeanceSalt)
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
	ui := newTerminalUI(os.Stderr)
	ctx, cancel := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer cancel()
	client, err := seanceapp.Connect(ctx, seanceapp.ClientConfig{
		Address: host + ":" + strconv.Itoa(int(port)), Nick: nick,
		Timeout: options.timeout, TimeoutSet: true, OnEvent: ui.event,
	}, &key)
	if err != nil {
		fmt.Fprintf(os.Stderr, "Failed to join room: %v\n", err)
		return 2
	}
	defer client.ZeroKey()
	printBanner()
	fmt.Fprintf(os.Stderr, "\x1b[38;5;245mNick:\x1b[0m %s\n\n", nick)
	if options.bot {
		return runBotMode(ctx, cancel, client, options)
	}
	fmt.Fprint(os.Stderr, "\x1b[38;5;141mConnected!\x1b[38;5;240m Type /quit to leave.\x1b[0m\n\n")
	done := make(chan error, 1)
	go func() { done <- client.Run(ctx) }()
	serviceDone, loopErr := runInteractive(ctx, ui, done, true, client.SendMessage)
	if !serviceDone {
		_ = client.SendLeave()
		_ = client.Close()
		<-done
	}
	if loopErr != nil && !errors.Is(loopErr, errQuit) && !errors.Is(loopErr, context.Canceled) {
		fmt.Fprintf(os.Stderr, "Connection lost: %v\n", loopErr)
		return 1
	}
	fmt.Fprintln(os.Stderr, "\nDisconnected.")
	return 0
}

func runBotMode(ctx context.Context, cancel context.CancelFunc, client *seanceapp.Client, options joinOptions) int {
	api, err := seanceapp.NewBotAPI(client, options.apiPort)
	if err != nil {
		fmt.Fprintf(os.Stderr, "Failed to start bot API: %v\n", err)
		_ = client.Close()
		return 1
	}
	fmt.Fprintf(os.Stderr, "Bot mode: HTTP API on http://127.0.0.1:%d\n", api.Port())
	fmt.Fprintln(os.Stderr, "  POST /send       - send a message")
	fmt.Fprintln(os.Stderr, "  GET  /messages   - get new messages")
	fmt.Fprintln(os.Stderr, "  GET  /peers      - list participants")
	fmt.Fprintln(os.Stderr, "  GET  /nick       - get bot's nick")
	fmt.Fprint(os.Stderr, "  POST /quit       - disconnect\n\n")
	clientDone := make(chan error, 1)
	go func() { clientDone <- client.Run(ctx) }()
	apiDone := make(chan error, 1)
	go func() { apiDone <- api.Run() }()
	var familiarDone <-chan error
	if options.familiar {
		done := make(chan error, 1)
		familiarDone = done
		go func() {
			err := familiarcore.Run(ctx, familiarcore.Config{APIHost: "127.0.0.1", APIPort: api.Port(), Logger: os.Stderr})
			if err != nil && !errors.Is(err, context.Canceled) {
				fmt.Fprintf(os.Stderr, "Familiar stopped: %v\n", err)
			}
			done <- err
		}()
	}
	var runErr error
	clientFinished, apiFinished := false, false
	select {
	case runErr = <-clientDone:
		clientFinished = true
	case runErr = <-apiDone:
		apiFinished = true
	case <-ctx.Done():
		runErr = ctx.Err()
	}
	cancel()
	_ = client.Close()
	shutdownCtx, stop := context.WithTimeout(context.Background(), 2*time.Second)
	_ = api.Close(shutdownCtx)
	stop()
	if !clientFinished {
		<-clientDone
	}
	if !apiFinished {
		<-apiDone
	}
	if familiarDone != nil {
		<-familiarDone
	}
	if runErr != nil && !errors.Is(runErr, context.Canceled) {
		fmt.Fprintf(os.Stderr, "Bot connection failed: %v\n", runErr)
		return 1
	}
	fmt.Fprintln(os.Stderr, "\nDisconnected.")
	return 0
}

func runInteractive(ctx context.Context, ui *terminalUI, service <-chan error, exitOnEOF bool, send func(string) error) (bool, error) {
	fd := int(os.Stdin.Fd())
	if term.IsTerminal(fd) {
		state, err := term.MakeRaw(fd)
		if err == nil {
			defer term.Restore(fd, state)
			ui.setRaw(true)
			defer ui.setRaw(false)
			bytesIn := make(chan byte, 1)
			go func() {
				var one [1]byte
				for {
					n, readErr := os.Stdin.Read(one[:])
					if readErr != nil || n == 0 {
						close(bytesIn)
						return
					}
					select {
					case bytesIn <- one[0]:
					case <-ctx.Done():
						return
					}
				}
			}()
			for {
				select {
				case err := <-service:
					return true, err
				case <-ctx.Done():
					return false, ctx.Err()
				case value, open := <-bytesIn:
					if !open {
						if exitOnEOF {
							return false, errQuit
						}
						bytesIn = nil
						continue
					}
					line, submitted, quit := ui.processByte(value)
					if quit {
						return false, errQuit
					}
					if submitted && line != "" {
						if err := send(line); err != nil {
							return false, err
						}
					}
				}
			}
		}
	}
	lines := boundedLines(os.Stdin, inputLimit)
	for {
		select {
		case err := <-service:
			return true, err
		case <-ctx.Done():
			return false, ctx.Err()
		case line, open := <-lines:
			if !open {
				if exitOnEOF {
					return false, errQuit
				}
				lines = nil
				continue
			}
			trimmed := strings.TrimSpace(line)
			if trimmed == "" {
				continue
			}
			if trimmed == "/quit" {
				return false, errQuit
			}
			if err := send(trimmed); err != nil {
				return false, err
			}
		}
	}
}

func boundedLines(reader io.Reader, maximum int) <-chan string {
	lines := make(chan string)
	go func() {
		defer close(lines)
		buffered := bufio.NewReaderSize(reader, min(maximum, 4096))
		line := make([]byte, 0, min(maximum, 4096))
		overlong := false
		for {
			fragment, err := buffered.ReadSlice('\n')
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

func printJoinCommands(host string, port uint16, password string) {
	fmt.Fprintf(os.Stderr, "  \x1b[38;5;240mseance join %s:%d --password %s\x1b[0m\n", host, port, password)
	fmt.Fprintf(os.Stderr, "  \x1b[38;5;240mseance join %s:%d --password %s --familiar\x1b[0m\n\n", host, port, password)
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

func printBanner() {
	fmt.Fprintln(os.Stderr, "\n\x1b[38;5;54m                ·  \x1b[38;5;183m✦\x1b[38;5;54m  ·\x1b[0m")
	fmt.Fprintln(os.Stderr, "\n\x1b[38;5;91m        ╔═╗ ╔═╗ ╔═╗ ╔╗╔ ╔═╗ ╔═╗\x1b[0m")
	fmt.Fprintln(os.Stderr, "\x1b[38;5;128m        ╚═╗ ║╣  ╠═╣ ║║║ ║   ║╣\x1b[0m")
	fmt.Fprintln(os.Stderr, "\x1b[38;5;177m        ╚═╝ ╚═╝ ╩ ╩ ╝╚╝ ╚═╝ ╚═╝\x1b[0m")
	fmt.Fprintln(os.Stderr, "\x1b[38;5;245m\n       ephemeral encrypted chat\x1b[0m")
	fmt.Fprintf(os.Stderr, "\x1b[38;5;240m                v%s\x1b[0m\n", version)
	fmt.Fprintln(os.Stderr, "\n\x1b[38;5;54m                ·  \x1b[38;5;183m✧\x1b[38;5;54m  ·\x1b[0m")
	fmt.Fprintln(os.Stderr)
}

func printUsage() {
	fmt.Fprint(os.Stderr, `Usage: seance <command> [options]

Commands:
  host              Create a chat room
  join <host:port>  Join a chat room

Host options:
  --port <port>        Local port (default: auto)
  --bore-port <port>   Request specific bore port
  --local              Skip tunnel, local only
  --password <pass>    Room password (default: auto-generated)
  --nick <name>        Your display name (default: auto-generated)
  --max-peers <n>      Max remote participants (default: 8)

Join options:
  --password <pass>    Room password (required)
  --nick <name>        Your display name (default: auto-generated)
  --timeout <secs>     Connect/initial-write timeout (default: 30)
  --bot                Bot mode: HTTP API instead of stdin
  --api-port <port>    Bot API port (default: 9999)
  --familiar           Bot mode + auto-start familiar daemon
`)
}
