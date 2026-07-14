package main

import (
	"context"
	"errors"
	"fmt"
	"math"
	"os"
	"os/signal"
	"strconv"
	"syscall"
	"time"

	"github.com/no-way-labs/cauldron/internal/cli"
	"github.com/no-way-labs/cauldron/internal/familiarcore"
)

var version = "0.0.0-dev"

func main() {
	os.Exit(run(os.Args[1:]))
}

func run(args []string) int {
	config := familiarcore.Config{
		APIHost: familiarcore.DefaultAPIHost, APIPort: familiarcore.DefaultAPIPort,
		ContextSize: familiarcore.DefaultContextSize, Model: familiarcore.DefaultModel,
		Cooldown: 2 * time.Second, CooldownSet: true,
	}
	var showHelp, showVersion bool
	options := map[string]cli.Option{
		"--help":    {Apply: func(string) error { showHelp = true; return nil }},
		"-h":        {Apply: func(string) error { showHelp = true; return nil }},
		"--version": {Apply: func(string) error { showVersion = true; return nil }},
		"-v":        {Apply: func(string) error { showVersion = true; return nil }},
		"--api-port": {TakesValue: true, Apply: func(value string) error {
			parsed, err := cli.PositiveUint16(value)
			if err != nil {
				return err
			}
			config.APIPort = parsed
			return nil
		}},
		"--api-host": {TakesValue: true, Apply: func(value string) error {
			config.APIHost = value
			return nil
		}},
		"--system": {TakesValue: true, AllowEmpty: true, Apply: func(value string) error {
			config.SystemPrompt = value
			return nil
		}},
		"--context": {TakesValue: true, Apply: func(value string) error {
			parsed, err := strconv.ParseInt(value, 10, 32)
			if err != nil || parsed < 1 {
				return errors.New("must be a positive integer")
			}
			config.ContextSize = int(parsed)
			return nil
		}},
		"--model": {TakesValue: true, Apply: func(value string) error {
			config.Model = value
			return nil
		}},
		"--cooldown": {TakesValue: true, Apply: func(value string) error {
			parsed, err := strconv.ParseUint(value, 10, 64)
			if err != nil || parsed > uint64(math.MaxInt64/int64(time.Second)) {
				return errors.New("must be a non-negative duration in seconds")
			}
			config.Cooldown = time.Duration(parsed) * time.Second
			config.CooldownSet = true
			return nil
		}},
	}
	if err := cli.Parse(args, options, nil); err != nil {
		fmt.Fprintln(os.Stderr, err)
		printUsage()
		return 1
	}
	if showHelp {
		printUsage()
		return 0
	}
	if showVersion {
		fmt.Fprintf(os.Stderr, "familiar %s\n", version)
		return 0
	}

	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer stop()
	if err := familiarcore.Run(ctx, config); err != nil && !errors.Is(err, context.Canceled) {
		fmt.Fprintf(os.Stderr, "familiar fatal: %v\n", err)
		return 1
	}
	return 0
}

func printUsage() {
	fmt.Fprintf(os.Stderr, `familiar %s - AI chat bot for seance rooms

Usage: familiar [options]

Requires ANTHROPIC_API_KEY environment variable.

Options:
  --api-port PORT  Seance bot API port (default: 9999)
  --api-host HOST  Seance bot API host (default: 127.0.0.1)
  --system PROMPT  System prompt / personality
  --context N      Messages to keep as context (default: 50)
  --model MODEL    Claude model (default: %s)
  --cooldown SECS  Seconds between responses (default: 2)
  -h, --help       Show this help
  -v, --version    Show version

`, version, familiarcore.DefaultModel)
}
