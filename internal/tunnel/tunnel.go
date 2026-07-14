// Package tunnel supervises the external bore client used by Cauldron hosts.
package tunnel

import (
	"bufio"
	"context"
	"errors"
	"fmt"
	"io"
	"os/exec"
	"strconv"
	"strings"
	"sync"
	"time"
)

var (
	ErrPortInUse = errors.New("tunnel: requested public port is in use")
	ErrTimeout   = errors.New("tunnel: bore startup timed out")
)

// Config controls bore process startup. Zero values select the production
// bore.pub contract; the injectable fields make process supervision testable.
type Config struct {
	Command        string
	PublicHost     string
	StartupTimeout time.Duration
	Logger         io.Writer
	Backoff        func(attempt int) time.Duration
}

func (config Config) defaults() Config {
	if config.Command == "" {
		config.Command = "bore"
	}
	if config.PublicHost == "" {
		config.PublicHost = "bore.pub"
	}
	if config.StartupTimeout == 0 {
		config.StartupTimeout = 10 * time.Second
	}
	if config.Logger == nil {
		config.Logger = io.Discard
	}
	if config.Backoff == nil {
		config.Backoff = func(attempt int) time.Duration {
			delay := time.Second << min(attempt, 30)
			if delay > 30*time.Second {
				return 30 * time.Second
			}
			return delay
		}
	}
	return config
}

type process struct {
	cmd  *exec.Cmd
	done <-chan error
}

type event struct {
	line   string
	stderr bool
}

// Info is an atomic snapshot of a tunnel's public and local endpoints.
type Info struct {
	PublicHost    string
	PublicPort    uint16
	RequestedPort uint16
	LocalPort     uint16
}

// Tunnel is a supervised bore process. StartMonitor must be called once after
// Establish; Close is idempotent and waits for the child and monitor to exit.
type Tunnel struct {
	config Config
	ctx    context.Context
	cancel context.CancelFunc

	mu            sync.Mutex
	publicHost    string
	publicPort    uint16
	requestedPort uint16
	localPort     uint16
	current       *process
	started       bool
	closed        bool
	wg            sync.WaitGroup
	logMu         sync.Mutex
}

// Establish starts bore and waits until it reports its public endpoint.
func Establish(ctx context.Context, localPort, requestedPort uint16, input Config) (*Tunnel, error) {
	config := input.defaults()
	process, publicPort, err := spawn(ctx, localPort, requestedPort, config)
	if err != nil {
		return nil, err
	}
	tunnelCtx, cancel := context.WithCancel(ctx)
	return &Tunnel{
		publicHost: config.PublicHost, publicPort: publicPort,
		requestedPort: requestedPort, localPort: localPort,
		config: config, ctx: tunnelCtx, cancel: cancel, current: process,
	}, nil
}

// Info returns a consistent endpoint snapshot while reconnect supervision may
// be changing the assigned public port.
func (tunnel *Tunnel) Info() Info {
	tunnel.mu.Lock()
	defer tunnel.mu.Unlock()
	return Info{
		PublicHost: tunnel.publicHost, PublicPort: tunnel.publicPort,
		RequestedPort: tunnel.requestedPort, LocalPort: tunnel.localPort,
	}
}

// StartMonitor begins reconnect supervision. Calling it more than once is safe.
func (tunnel *Tunnel) StartMonitor() {
	tunnel.mu.Lock()
	if tunnel.started || tunnel.closed {
		tunnel.mu.Unlock()
		return
	}
	tunnel.started = true
	tunnel.wg.Add(1)
	tunnel.mu.Unlock()
	go tunnel.monitor()
}

func (tunnel *Tunnel) monitor() {
	defer tunnel.wg.Done()
	for {
		tunnel.mu.Lock()
		current := tunnel.current
		localPort := tunnel.localPort
		publicPort := tunnel.publicPort
		tunnel.mu.Unlock()
		if current == nil {
			return
		}

		select {
		case <-tunnel.ctx.Done():
			return
		case <-current.done:
		}
		if tunnel.ctx.Err() != nil {
			return
		}
		tunnel.logf("\nTunnel dropped, reconnecting...\n")

		reconnected := false
		for attempt := 0; attempt < 10; attempt++ {
			if !sleep(tunnel.ctx, tunnel.config.Backoff(attempt)) {
				return
			}
			process, port, err := spawn(tunnel.ctx, localPort, publicPort, tunnel.config)
			if err != nil {
				if tunnel.ctx.Err() != nil {
					return
				}
				tunnel.logf("Reconnect attempt %d/%d failed\n", attempt+1, 10)
				continue
			}

			tunnel.mu.Lock()
			if tunnel.closed {
				tunnel.mu.Unlock()
				stopProcess(process)
				return
			}
			oldPort := tunnel.publicPort
			tunnel.publicPort = port
			tunnel.current = process
			publicHost := tunnel.publicHost
			tunnel.mu.Unlock()
			if port == oldPort {
				tunnel.logf("Tunnel reconnected: %s:%d\n", publicHost, port)
			} else {
				tunnel.logf("Tunnel reconnected on new port: %s:%d\n", publicHost, port)
			}
			reconnected = true
			break
		}
		if !reconnected {
			tunnel.logf("Could not reconnect tunnel after %d attempts. Running local-only.\n", 10)
			return
		}
	}
}

// Close stops the current process and waits for monitor shutdown.
func (tunnel *Tunnel) Close() error {
	tunnel.mu.Lock()
	if tunnel.closed {
		tunnel.mu.Unlock()
		return nil
	}
	tunnel.closed = true
	tunnel.cancel()
	current := tunnel.current
	tunnel.mu.Unlock()
	if current != nil {
		stopProcess(current)
	}
	tunnel.wg.Wait()
	return nil
}

func (tunnel *Tunnel) logf(format string, args ...any) {
	tunnel.logMu.Lock()
	defer tunnel.logMu.Unlock()
	fmt.Fprintf(tunnel.config.Logger, format, args...)
}

func spawn(parent context.Context, localPort, requestedPort uint16, config Config) (*process, uint16, error) {
	args := []string{"local", strconv.Itoa(int(localPort)), "--to", config.PublicHost}
	if requestedPort > 0 {
		args = append(args, "--port", strconv.Itoa(int(requestedPort)))
	}
	cmd := exec.Command(config.Command, args...)
	stdout, err := cmd.StdoutPipe()
	if err != nil {
		return nil, 0, fmt.Errorf("tunnel: bore stdout: %w", err)
	}
	stderr, err := cmd.StderrPipe()
	if err != nil {
		return nil, 0, fmt.Errorf("tunnel: bore stderr: %w", err)
	}
	if err := cmd.Start(); err != nil {
		return nil, 0, fmt.Errorf("tunnel: start bore: %w", err)
	}

	events := make(chan event, 64)
	var drains sync.WaitGroup
	drains.Add(2)
	go drain(&drains, stdout, false, events)
	go drain(&drains, stderr, true, events)
	waited := make(chan error, 1)
	go func() {
		err := cmd.Wait()
		drains.Wait()
		waited <- err
		close(waited)
	}()
	proc := &process{cmd: cmd, done: waited}

	startup := time.NewTimer(config.StartupTimeout)
	defer startup.Stop()
	prefix := "listening at " + config.PublicHost + ":"
	for {
		select {
		case <-parent.Done():
			stopProcess(proc)
			return nil, 0, parent.Err()
		case <-startup.C:
			stopProcess(proc)
			return nil, 0, ErrTimeout
		case err := <-waited:
			if err == nil {
				err = errors.New("bore exited before reporting an endpoint")
			}
			return nil, 0, fmt.Errorf("tunnel: %w", err)
		case item := <-events:
			lower := strings.ToLower(item.line)
			if item.stderr && (strings.Contains(lower, "address already in use") ||
				(strings.Contains(lower, "port") && strings.Contains(lower, "in use"))) {
				stopProcess(proc)
				return nil, 0, ErrPortInUse
			}
			position := strings.Index(item.line, prefix)
			if position < 0 {
				continue
			}
			portText := strings.TrimSpace(item.line[position+len(prefix):])
			port, parseErr := strconv.ParseUint(portText, 10, 16)
			if parseErr != nil || port == 0 {
				stopProcess(proc)
				return nil, 0, fmt.Errorf("tunnel: invalid public port %q", portText)
			}
			return proc, uint16(port), nil
		}
	}
}

func drain(group *sync.WaitGroup, reader io.Reader, stderr bool, events chan<- event) {
	defer group.Done()
	scanner := bufio.NewScanner(reader)
	scanner.Buffer(make([]byte, 4096), 1<<20)
	for scanner.Scan() {
		select {
		case events <- event{line: scanner.Text(), stderr: stderr}:
		default:
		}
	}
}

func stopProcess(process *process) {
	if process == nil {
		return
	}
	if process.cmd.Process != nil {
		_ = process.cmd.Process.Kill()
	}
	<-process.done
}

func sleep(ctx context.Context, duration time.Duration) bool {
	if duration <= 0 {
		return ctx.Err() == nil
	}
	timer := time.NewTimer(duration)
	defer timer.Stop()
	select {
	case <-ctx.Done():
		return false
	case <-timer.C:
		return true
	}
}
