package itest

import (
	"bytes"
	"encoding/json"
	"errors"
	"io"
	"net"
	"net/http"
	"os"
	"os/exec"
	"path/filepath"
	"strconv"
	"strings"
	"sync"
	"testing"
	"time"
)

func TestGoReleaseBinariesReportInjectedVersion(t *testing.T) {
	version := os.Getenv("CAULDRON_EXPECT_VERSION")
	if version == "" {
		t.Skip("set CAULDRON_EXPECT_VERSION and CAULDRON_GO_* binary paths")
	}
	for _, app := range []string{"mitt", "seance", "familiar", "omen", "covenant"} {
		binary := requireBinaryEnv(t, "CAULDRON_GO_"+strings.ToUpper(app))
		command := exec.Command(binary, "--version")
		output, err := command.CombinedOutput()
		if err != nil {
			t.Fatalf("%s --version: %v\n%s", app, err, output)
		}
		if got := string(output); !strings.Contains(got, version) {
			t.Fatalf("%s --version = %q, want injected %q", app, got, version)
		}
	}
}

func TestMittGoBinaryEndToEnd(t *testing.T) {
	binary := os.Getenv("CAULDRON_GO_MITT")
	if binary == "" {
		t.Skip("set CAULDRON_GO_MITT to run executable integration")
	}
	runMittDirection(t, binary, binary)
}

func TestSeanceGoBinariesAndBotAPI(t *testing.T) {
	binary := os.Getenv("CAULDRON_GO_SEANCE")
	if binary == "" {
		t.Skip("set CAULDRON_GO_SEANCE to run executable integration")
	}
	roomPort, apiPort := freePort(t), freePort(t)
	for apiPort == roomPort {
		apiPort = freePort(t)
	}
	host := startCommand(t, binary, "host", "--local", "--port", strconv.Itoa(roomPort),
		"--password", "integration-room", "--nick", "host")
	defer host.stop()
	host.waitForLog(t, "Waiting for participants", 5*time.Second)

	bot := startCommand(t, binary, "join", net.JoinHostPort("localhost", strconv.Itoa(roomPort)),
		"--password", "integration-room", "--nick", "bot", "--bot", "--api-port", strconv.Itoa(apiPort))
	defer bot.stop()
	baseURL := "http://" + net.JoinHostPort("127.0.0.1", strconv.Itoa(apiPort))
	waitHTTP(t, baseURL+"/health", 5*time.Second)

	var nick map[string]string
	getJSON(t, baseURL+"/nick", &nick)
	if nick["nick"] != "bot" {
		t.Fatalf("bot nick = %#v", nick)
	}
	var peers []string
	getJSON(t, baseURL+"/peers", &peers)
	if !sameStrings(peers, []string{"host", "bot"}) {
		t.Fatalf("seance peers = %#v", peers)
	}

	postBody(t, baseURL+"/send", "from-bot")
	host.waitForLog(t, "from-bot", 5*time.Second)
	host.writeLine(t, "from-host")
	waitForBotMessage(t, baseURL, "from-host", 5*time.Second)

	postBody(t, baseURL+"/quit", "")
	bot.waitExit(t, 0, 5*time.Second)
	host.writeLine(t, "/quit")
	host.waitExit(t, 0, 5*time.Second)
}

func TestCovenantGoBinariesSealAndVerify(t *testing.T) {
	binary := os.Getenv("CAULDRON_GO_COVENANT")
	if binary == "" {
		t.Skip("set CAULDRON_GO_COVENANT to run executable integration")
	}
	port := freePort(t)
	directory := t.TempDir()
	hostArtifact := filepath.Join(directory, "host-covenant.json")
	memberArtifact := filepath.Join(directory, "member-covenant.json")
	host := startCommand(t, binary, "host", "Integration Team", "--local", "--port", strconv.Itoa(port),
		"--password", "integration-covenant", "--identity", "host identity phrase",
		"--nick", "host", "--output", hostArtifact)
	defer host.stop()
	host.waitForLog(t, "Waiting for members", 8*time.Second)

	member := startCommand(t, binary, "join", net.JoinHostPort("localhost", strconv.Itoa(port)),
		"--password", "integration-covenant", "--identity", "member identity phrase",
		"--nick", "member", "--output", memberArtifact)
	defer member.stop()
	host.waitForLog(t, "member joined", 8*time.Second)
	startInteractivePhase(t, host, "/seal", "Sealing covenant", 8*time.Second)

	member.waitExit(t, 0, 12*time.Second)
	host.waitExit(t, 0, 12*time.Second)
	assertEqualFiles(t, hostArtifact, memberArtifact)
	assertArtifactVersion(t, hostArtifact, "covenant_version")
	output := runCommand(t, 0, binary, "verify", hostArtifact)
	if !strings.Contains(output, "All roster signatures valid") || !strings.Contains(output, "not signed in covenant v1") {
		t.Fatalf("covenant verify output omitted scope:\n%s", output)
	}
	if output = runCommand(t, 0, binary, "members", hostArtifact); !strings.Contains(output, "Integration Team") {
		t.Fatalf("covenant members output:\n%s", output)
	}
}

func TestOmenGoBinariesVoteAndVerify(t *testing.T) {
	binary := os.Getenv("CAULDRON_GO_OMEN")
	if binary == "" {
		t.Skip("set CAULDRON_GO_OMEN to run executable integration")
	}
	port := freePort(t)
	directory := t.TempDir()
	hostArtifact := filepath.Join(directory, "host-omen.json")
	voterArtifact := filepath.Join(directory, "voter-omen.json")
	host := startCommand(t, binary, "host", "Integration vote?", "--options", "yes,no", "--local",
		"--port", strconv.Itoa(port), "--password", "integration-omen", "--identity", "host omen identity",
		"--nick", "host", "--output", hostArtifact)
	defer host.stop()
	host.waitForLog(t, "Waiting for voters", 8*time.Second)

	voter := startCommand(t, binary, "join", net.JoinHostPort("localhost", strconv.Itoa(port)),
		"--password", "integration-omen", "--identity", "voter omen identity",
		"--nick", "voter", "--output", voterArtifact)
	defer voter.stop()
	voter.writeLine(t, "2")
	host.waitForLog(t, "voter joined", 8*time.Second)
	startInteractivePhase(t, host, "/start", "Vote started", 8*time.Second)
	host.writeLine(t, "1")

	voter.waitExit(t, 0, 15*time.Second)
	host.waitExit(t, 0, 15*time.Second)
	assertEqualFiles(t, hostArtifact, voterArtifact)
	assertArtifactVersion(t, hostArtifact, "omen_version")
	output := runCommand(t, 0, binary, "verify", hostArtifact)
	if !strings.Contains(output, "authentic and internally consistent") || !strings.Contains(output, "does not provide ballot anonymity") {
		t.Fatalf("omen verify output omitted integrity/privacy scope:\n%s", output)
	}
}

type runningCommand struct {
	cmd   *exec.Cmd
	stdin io.WriteCloser
	logs  synchronizedBuffer
	done  chan struct{}

	mu       sync.Mutex
	waitErr  error
	finished bool
}

func startCommand(t *testing.T, binary string, args ...string) *runningCommand {
	t.Helper()
	process := &runningCommand{cmd: exec.Command(binary, args...), done: make(chan struct{})}
	stdin, err := process.cmd.StdinPipe()
	if err != nil {
		t.Fatal(err)
	}
	process.stdin = stdin
	process.cmd.Stdout = &process.logs
	process.cmd.Stderr = &process.logs
	if err := process.cmd.Start(); err != nil {
		t.Fatalf("start %s %s: %v", binary, strings.Join(args, " "), err)
	}
	go func() {
		err := process.cmd.Wait()
		process.mu.Lock()
		process.waitErr, process.finished = err, true
		process.mu.Unlock()
		close(process.done)
	}()
	return process
}

func (process *runningCommand) writeLine(t *testing.T, line string) {
	t.Helper()
	if _, err := io.WriteString(process.stdin, line+"\n"); err != nil {
		t.Fatalf("write %q to process: %v\n%s", line, err, process.logs.String())
	}
}

func (process *runningCommand) waitForLog(t *testing.T, text string, timeout time.Duration) {
	t.Helper()
	deadline := time.Now().Add(timeout)
	for time.Now().Before(deadline) {
		if strings.Contains(process.logs.String(), text) {
			return
		}
		select {
		case <-process.done:
			t.Fatalf("process exited before logging %q:\n%s", text, process.logs.String())
		default:
		}
		time.Sleep(10 * time.Millisecond)
	}
	t.Fatalf("timed out waiting for log %q:\n%s", text, process.logs.String())
}

func (process *runningCommand) waitExit(t *testing.T, want int, timeout time.Duration) {
	t.Helper()
	select {
	case <-process.done:
	case <-time.After(timeout):
		process.stop()
		t.Fatalf("process did not exit in %s:\n%s", timeout, process.logs.String())
	}
	process.mu.Lock()
	err := process.waitErr
	process.mu.Unlock()
	exit := exitCode(err)
	if exit != want {
		t.Fatalf("process exit = %d, want %d (%v):\n%s", exit, want, err, process.logs.String())
	}
}

func (process *runningCommand) stop() {
	process.mu.Lock()
	finished := process.finished
	process.mu.Unlock()
	if finished {
		return
	}
	_ = process.cmd.Process.Kill()
	select {
	case <-process.done:
	case <-time.After(2 * time.Second):
	}
}

type synchronizedBuffer struct {
	mu sync.Mutex
	b  bytes.Buffer
}

func (buffer *synchronizedBuffer) Write(data []byte) (int, error) {
	buffer.mu.Lock()
	defer buffer.mu.Unlock()
	return buffer.b.Write(data)
}

func (buffer *synchronizedBuffer) String() string {
	buffer.mu.Lock()
	defer buffer.mu.Unlock()
	return buffer.b.String()
}

func freePort(t *testing.T) int {
	t.Helper()
	listener, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	port := listener.Addr().(*net.TCPAddr).Port
	if err := listener.Close(); err != nil {
		t.Fatal(err)
	}
	return port
}

func startInteractivePhase(t *testing.T, host *runningCommand, command, success string, timeout time.Duration) {
	t.Helper()
	deadline := time.Now().Add(timeout)
	for time.Now().Before(deadline) {
		if strings.Contains(host.logs.String(), success) {
			return
		}
		host.writeLine(t, command)
		time.Sleep(50 * time.Millisecond)
	}
	t.Fatalf("phase %s did not start:\n%s", success, host.logs.String())
}

func waitHTTP(t *testing.T, endpoint string, timeout time.Duration) {
	t.Helper()
	deadline := time.Now().Add(timeout)
	for time.Now().Before(deadline) {
		response, err := integrationHTTPClient.Get(endpoint)
		if err == nil {
			response.Body.Close()
			if response.StatusCode == http.StatusOK {
				return
			}
		}
		time.Sleep(20 * time.Millisecond)
	}
	t.Fatalf("HTTP endpoint did not become ready: %s", endpoint)
}

var integrationHTTPClient = &http.Client{Timeout: 2 * time.Second}

func getJSON(t *testing.T, endpoint string, target any) {
	t.Helper()
	response, err := integrationHTTPClient.Get(endpoint)
	if err != nil {
		t.Fatal(err)
	}
	defer response.Body.Close()
	if response.StatusCode != http.StatusOK {
		t.Fatalf("GET %s returned %s", endpoint, response.Status)
	}
	if err := json.NewDecoder(response.Body).Decode(target); err != nil {
		t.Fatal(err)
	}
}

func postBody(t *testing.T, endpoint, body string) {
	t.Helper()
	request, err := http.NewRequest(http.MethodPost, endpoint, strings.NewReader(body))
	if err != nil {
		t.Fatal(err)
	}
	response, err := integrationHTTPClient.Do(request)
	if err != nil {
		t.Fatal(err)
	}
	defer response.Body.Close()
	if response.StatusCode != http.StatusOK {
		data, _ := io.ReadAll(response.Body)
		t.Fatalf("POST %s returned %s: %s", endpoint, response.Status, data)
	}
}

func waitForBotMessage(t *testing.T, baseURL, content string, timeout time.Duration) {
	t.Helper()
	type message struct {
		Content string `json:"content"`
	}
	deadline := time.Now().Add(timeout)
	for time.Now().Before(deadline) {
		var messages []message
		getJSON(t, baseURL+"/messages?since=0&wait=1", &messages)
		for _, item := range messages {
			if item.Content == content {
				return
			}
		}
	}
	t.Fatalf("bot API did not receive %q", content)
}

func assertEqualFiles(t *testing.T, first, second string) {
	t.Helper()
	firstData, firstErr := os.ReadFile(first)
	secondData, secondErr := os.ReadFile(second)
	if firstErr != nil || secondErr != nil {
		t.Fatalf("read artifacts: %v, %v", firstErr, secondErr)
	}
	if !bytes.Equal(firstData, secondData) {
		t.Fatalf("artifacts differ:\n%s\n%s", firstData, secondData)
	}
}

func assertArtifactVersion(t *testing.T, path, field string) {
	t.Helper()
	want := os.Getenv("CAULDRON_EXPECT_VERSION")
	if want == "" {
		return
	}
	data, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	var artifact map[string]any
	if err := json.Unmarshal(data, &artifact); err != nil {
		t.Fatal(err)
	}
	if artifact[field] != want {
		t.Fatalf("%s field = %#v, want %q", field, artifact[field], want)
	}
}

func runCommand(t *testing.T, wantExit int, binary string, args ...string) string {
	t.Helper()
	command := exec.Command(binary, args...)
	output, err := command.CombinedOutput()
	if got := exitCode(err); got != wantExit {
		t.Fatalf("%s %s exit = %d, want %d: %v\n%s", binary, strings.Join(args, " "), got, wantExit, err, output)
	}
	return string(output)
}

func exitCode(err error) int {
	if err == nil {
		return 0
	}
	var exitError *exec.ExitError
	if errors.As(err, &exitError) {
		return exitError.ExitCode()
	}
	return -1
}

func sameStrings(first, second []string) bool {
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

func requireBinaryEnv(t *testing.T, name string) string {
	t.Helper()
	value := os.Getenv(name)
	if value == "" {
		t.Fatalf("%s is required when CAULDRON_EXPECT_VERSION is set", name)
	}
	return value
}
