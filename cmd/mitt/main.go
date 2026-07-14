package main

import (
	"context"
	"errors"
	"fmt"
	"math"
	"os"
	"os/signal"
	"strconv"
	"strings"
	"syscall"
	"time"

	"github.com/no-way-labs/cauldron/internal/cli"
	"github.com/no-way-labs/cauldron/internal/ident"
	mittapp "github.com/no-way-labs/cauldron/internal/mitt"
	"github.com/no-way-labs/cauldron/internal/secretbox"
	"github.com/no-way-labs/cauldron/internal/tunnel"
)

var version = "0.0.0-dev"

func main() {
	os.Exit(run(os.Args[1:]))
}

func run(args []string) int {
	if len(args) == 0 {
		printUsage()
		return 0
	}
	if args[0] == "--version" {
		fmt.Fprintf(os.Stderr, "mitt %s\n", version)
		return 0
	}
	switch args[0] {
	case "open":
		return runOpen(args[1:])
	case "send":
		return runSend(args[1:])
	default:
		fmt.Fprintf(os.Stderr, "Unknown command: %s\n", args[0])
		printUsage()
		return 1
	}
}

type openOptions struct {
	port, borePort uint16
	dir            string
	toStdout       bool
	localOnly      bool
	quiet          bool
	accept, reject []string
	maxSize        uint64
	password       string
	passwordSet    bool
}

func runOpen(args []string) int {
	options := openOptions{dir: "./inbox", maxSize: mittapp.DefaultMaxSize}
	flags := map[string]cli.Option{
		"--port": {TakesValue: true, Apply: func(value string) error {
			parsed, err := cli.PositiveUint16(value)
			options.port = parsed
			return err
		}},
		"--bore-port": {TakesValue: true, Apply: func(value string) error {
			parsed, err := cli.Uint16(value)
			options.borePort = parsed
			return err
		}},
		"--dir":    {TakesValue: true, Apply: func(value string) error { options.dir = value; return nil }},
		"--stdout": {Apply: func(string) error { options.toStdout = true; return nil }},
		"--local":  {Apply: func(string) error { options.localOnly = true; return nil }},
		"--quiet":  {Apply: func(string) error { options.quiet = true; return nil }},
		"--accept": {TakesValue: true, Apply: func(value string) error {
			options.accept = parseGlobs(value)
			return nil
		}},
		"--reject": {TakesValue: true, Apply: func(value string) error {
			options.reject = parseGlobs(value)
			return nil
		}},
		"--max-size": {TakesValue: true, Apply: func(value string) error {
			parsed, err := cli.Uint64(value)
			if err != nil {
				return err
			}
			if parsed > mittapp.MaxPayloadBytes {
				return fmt.Errorf("must not exceed %d", mittapp.MaxPayloadBytes)
			}
			options.maxSize = parsed
			return nil
		}},
		"--password": {TakesValue: true, Apply: func(value string) error {
			options.password, options.passwordSet = value, true
			return nil
		}},
	}
	if err := cli.Parse(args, flags, nil); err != nil {
		fmt.Fprintf(os.Stderr, "Error: %v\n", err)
		printUsage()
		return 1
	}
	if options.port > 0 && options.port < 1024 {
		fmt.Fprintf(os.Stderr, "Warning: Port %d requires root/admin privileges\n", options.port)
	}
	password, found, err := cli.ResolveSecret(options.passwordSet, options.password, "MITT_PASSWORD")
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
	key, err := secretbox.Derive(password, secretbox.MittSalt)
	if err != nil {
		fmt.Fprintf(os.Stderr, "Fatal: key derivation failed: %v\n", err)
		return 1
	}
	defer secretbox.ZeroKey(&key)

	config := mittapp.DefaultServerConfig()
	config.Dir, config.ToStdout, config.Stdout, config.Logger = options.dir, options.toStdout, os.Stdout, os.Stderr
	config.Accept, config.Reject, config.MaxSize = options.accept, options.reject, options.maxSize
	server, err := mittapp.NewServer(options.port, config, &key)
	if err != nil {
		fmt.Fprintf(os.Stderr, "Fatal: could not start server: %v\n", err)
		return 1
	}
	defer server.Close()

	if !options.quiet {
		fmt.Fprintf(os.Stderr, "\n🔐 Password: %s\n", password)
	}
	fmt.Fprintf(os.Stderr, "Local: localhost:%d\n\n", server.Port())

	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer stop()
	var activeTunnel *tunnel.Tunnel
	if !options.localOnly {
		activeTunnel, err = tunnel.Establish(ctx, server.Port(), options.borePort, tunnel.Config{Logger: os.Stderr})
		if errors.Is(err, tunnel.ErrPortInUse) && options.borePort > 0 {
			fmt.Fprintf(os.Stderr, "Bore port %d is already in use, trying random port...\n", options.borePort)
			activeTunnel, err = tunnel.Establish(ctx, server.Port(), 0, tunnel.Config{Logger: os.Stderr})
		}
		if err != nil {
			fmt.Fprintf(os.Stderr, "Warning: Could not establish tunnel (%v)\n", err)
			fmt.Fprintln(os.Stderr, "Running in local-only mode.")
			fmt.Fprintln(os.Stderr)
		} else {
			activeTunnel.StartMonitor()
			defer activeTunnel.Close()
			info := activeTunnel.Info()
			fmt.Fprintf(os.Stderr, "Public: %s:%d", info.PublicHost, info.PublicPort)
			if info.RequestedPort > 0 && info.RequestedPort != info.PublicPort {
				fmt.Fprintf(os.Stderr, " (requested %d but port was unavailable)", info.RequestedPort)
			}
			fmt.Fprintln(os.Stderr)
		}
	}
	if !options.quiet {
		if activeTunnel != nil {
			info := activeTunnel.Info()
			fmt.Fprintln(os.Stderr, "\nTo send a file:")
			fmt.Fprintf(os.Stderr, "  mitt send %s:%d <file> --password %s\n\n", info.PublicHost, info.PublicPort, password)
		} else {
			fmt.Fprintln(os.Stderr, "To send a file:")
			fmt.Fprintf(os.Stderr, "  mitt send localhost:%d <file> --password %s\n\n", server.Port(), password)
		}
	}
	fmt.Fprintln(os.Stderr, "Waiting for files...")
	fmt.Fprintln(os.Stderr)
	if err := server.Serve(ctx); err != nil {
		fmt.Fprintf(os.Stderr, "Fatal: server failed: %v\n", err)
		return 1
	}
	return 0
}

type sendOptions struct {
	positionals []string
	text        string
	textSet     bool
	timeout     time.Duration
	password    string
	passwordSet bool
}

func runSend(args []string) int {
	if len(args) == 0 {
		fmt.Fprintln(os.Stderr, "Usage: mitt send <host:port> [<payload>] --password <pass> [--text <text>]")
		return 1
	}
	options := sendOptions{timeout: 30 * time.Second}
	flags := map[string]cli.Option{
		"--text": {TakesValue: true, AllowEmpty: true, Apply: func(value string) error {
			options.text, options.textSet = value, true
			return nil
		}},
		"--timeout": {TakesValue: true, Apply: func(value string) error {
			seconds, err := cli.Uint64(value)
			if err != nil || seconds > uint64(math.MaxInt64/int64(time.Second)) {
				return errors.New("must be a non-negative duration in seconds")
			}
			options.timeout = time.Duration(seconds) * time.Second
			return nil
		}},
		"--password": {TakesValue: true, Apply: func(value string) error {
			options.password, options.passwordSet = value, true
			return nil
		}},
	}
	if err := cli.Parse(args, flags, func(value string) error {
		if len(options.positionals) >= 2 {
			return fmt.Errorf("unexpected argument %s", value)
		}
		options.positionals = append(options.positionals, value)
		return nil
	}); err != nil {
		fmt.Fprintf(os.Stderr, "Error: %v\n", err)
		return 1
	}
	if len(options.positionals) == 0 {
		fmt.Fprintln(os.Stderr, "Error: target is required")
		return 1
	}
	host, port, err := cli.SplitTargetFirst(options.positionals[0])
	if err != nil {
		fmt.Fprintln(os.Stderr, "Error: target must be in format host:port")
		return 1
	}
	password, found, err := cli.ResolveSecret(options.passwordSet, options.password, "MITT_PASSWORD")
	if err != nil {
		fmt.Fprintf(os.Stderr, "Error: %v\n", err)
		return 1
	}
	if !found {
		fmt.Fprintln(os.Stderr, "Error: --password (or MITT_PASSWORD) is required")
		return 1
	}
	defer secretbox.Zero(password)
	var payload mittapp.Payload
	if options.textSet {
		payload = mittapp.TextPayload(options.text)
	} else if len(options.positionals) == 2 {
		if options.positionals[1] == "-" {
			payload = mittapp.StdinPayload(os.Stdin)
		} else {
			payload = mittapp.FilePayload(options.positionals[1])
		}
	} else {
		fmt.Fprintln(os.Stderr, "Error: Must provide either a file path or --text flag")
		return 1
	}
	key, err := secretbox.Derive(password, secretbox.MittSalt)
	if err != nil {
		fmt.Fprintf(os.Stderr, "Fatal: key derivation failed: %v\n", err)
		return 1
	}
	defer secretbox.ZeroKey(&key)
	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer stop()
	address := host + ":" + strconv.Itoa(int(port))
	err = mittapp.Send(ctx, address, payload, &key, options.timeout)
	if err == nil {
		fmt.Fprintln(os.Stderr, "Delivered.")
		return 0
	}
	if errors.Is(err, mittapp.ErrTimeout) {
		fmt.Fprintln(os.Stderr, "Timeout: server did not respond")
		return 2
	}
	fmt.Fprintf(os.Stderr, "Failed: %v\n", err)
	return 2
}

func parseGlobs(value string) []string {
	var result []string
	for _, item := range strings.Split(value, ",") {
		if item != "" {
			result = append(result, item)
		}
	}
	return result
}

func printUsage() {
	fmt.Fprint(os.Stderr, `Usage: mitt <command> [options]

Commands:
  open              Start a server to receive files
  send <host:port> <payload>  Send a file to an open mitt

Open options:
  --port <port>     Local port (default: random)
  --bore-port <port> Remote bore port to request (default: random)
  --local           Local only, no tunnel (for testing)
  --quiet           Don't display password in output
  --dir <path>      Save directory (default: ./inbox)
  --stdout          Print to stdout instead of saving
  --accept <globs>  Whitelist (e.g., *.txt,*.csv)
  --reject <globs>  Blacklist (e.g., *.exe)
  --max-size <bytes> Max file size (default: 100mb)
  --password <pass> Encryption password (default: auto-generated)

Send options:
  --text <string>   Send literal text
  --timeout <seconds> Wait time (default: 30)
  --password <pass> Encryption password (required)

Global options:
  --version         Show version

`)
}
