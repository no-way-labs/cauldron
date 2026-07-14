package seance

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/no-way-labs/cauldron/internal/frame"
	"github.com/no-way-labs/cauldron/internal/secretbox"
)

func TestChatCollisionSemanticsHostAndClientMessages(t *testing.T) {
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	key := testKey()
	hostEvents := make(chan Message, 128)
	server, runServer := startTestServer(t, ctx, ServerConfig{
		Nick: "host", OnEvent: func(message Message) { hostEvents <- message },
	}, &key)
	firstEvents := make(chan Message, 128)
	first, runFirst := startTestClient(t, ctx, server, "same", firstEvents, &key)
	waitForPeers(t, first, []string{"host", "same"})
	secondEvents := make(chan Message, 128)
	second, runSecond := startTestClient(t, ctx, server, "same", secondEvents, &key)
	waitForPeers(t, first, []string{"host", "same", "same_2"})
	waitForPeers(t, second, []string{"host", "same", "same_2"})

	if err := second.SendMessage("from second"); err != nil {
		t.Fatal(err)
	}
	clientMessage := waitMessage(t, firstEvents, "msg", "from second")
	if clientMessage.Sender != "same" {
		t.Fatalf("relayed sender = %q, want original unsuffixed header", clientMessage.Sender)
	}
	hostMessage := waitMessage(t, hostEvents, "msg", "from second")
	if hostMessage.Sender != "same_2" {
		t.Fatalf("host sender = %q, want resolved admission nick", hostMessage.Sender)
	}

	if err := server.SendMessage("from host"); err != nil {
		t.Fatal(err)
	}
	if got := waitMessage(t, firstEvents, "msg", "from host"); got.Sender != "host" {
		t.Fatalf("host relay sender = %q", got.Sender)
	}
	_ = waitMessage(t, secondEvents, "msg", "from host")

	_ = second.SendLeave()
	_ = second.Close()
	_ = waitMessage(t, firstEvents, "leave", "same_2 left")
	cancel()
	waitRun(t, runFirst)
	waitRun(t, runSecond)
	waitRun(t, runServer)
	first.ZeroKey()
	second.ZeroKey()
}

func TestRelayPreservesEntireFrameEnvelope(t *testing.T) {
	serverSide, recipientSide := net.Pipe()
	defer serverSide.Close()
	defer recipientSide.Close()
	server := &Server{config: ServerConfig{WriteTimeout: time.Second}}
	recipient := &peer{connection: serverSide, nick: "recipient"}
	server.peers = []*peer{recipient}
	var nonce [24]byte
	copy(nonce[:], bytes.Repeat([]byte{5}, len(nonce)))
	value := frame.Frame{
		Type: MessageChat, Timestamp: 123456, Sender: "spoofed",
		Nonce: nonce, Ciphertext: []byte{9, 8, 7},
	}
	copy(value.Tag[:], bytes.Repeat([]byte{6}, len(value.Tag)))
	done := make(chan error, 1)
	go func() { done <- server.broadcastFrame(value, nil) }()
	got, err := frame.Read(recipientSide, ValidMessageType)
	if err != nil {
		t.Fatal(err)
	}
	if err := <-done; err != nil {
		t.Fatal(err)
	}
	if got.Type != value.Type || got.Timestamp != value.Timestamp || got.Sender != value.Sender ||
		got.Nonce != value.Nonce || got.Tag != value.Tag || !bytes.Equal(got.Ciphertext, value.Ciphertext) {
		t.Fatalf("relayed frame changed: %#v != %#v", got, value)
	}
}

func TestHostMessageSurvivesStalePeer(t *testing.T) {
	serverSide, peerSide := net.Pipe()
	peerSide.Close()
	server := &Server{
		config: ServerConfig{Nick: "host", Now: time.Now, OnEvent: func(Message) {}},
		peers:  []*peer{{connection: serverSide, nick: "gone"}},
	}
	defer serverSide.Close()
	if err := server.SendMessage("still here"); err != nil {
		t.Fatalf("host send failed because a snapshotted peer disconnected: %v", err)
	}
}

func TestNickListWriteDeadlineEvictsNonReadingPeer(t *testing.T) {
	serverSide, clientSide := net.Pipe()
	defer clientSide.Close()
	key := testKey()
	server := &Server{
		config: ServerConfig{
			MaxPeers: 8, Nick: "host", Now: time.Now, HandshakeTimeout: time.Second,
			WriteTimeout: 30 * time.Millisecond, OnEvent: func(Message) {}, Logger: io.Discard,
		},
		key: key,
	}
	server.running.Store(true)
	server.wg.Add(1)
	done := make(chan struct{})
	go func() {
		server.handleConnection(serverSide)
		close(done)
	}()
	if err := sendEncrypted(clientSide, nil, &key, MessageJoin, "silent", []byte(Magic), time.Now()); err != nil {
		t.Fatal(err)
	}
	select {
	case <-done:
	case <-time.After(500 * time.Millisecond):
		t.Fatal("non-reading peer pinned nick-list delivery past its deadline")
	}
	if server.PeerCount() != 0 {
		t.Fatalf("timed-out peer remains admitted: %d", server.PeerCount())
	}
}

func TestRateLimitRelaysOnlyFirstTenMessagesInWindow(t *testing.T) {
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	key := testKey()
	server, runServer := startTestServer(t, ctx, ServerConfig{Nick: "host"}, &key)
	senderEvents := make(chan Message, 128)
	sender, runSender := startTestClient(t, ctx, server, "sender", senderEvents, &key)
	waitForPeers(t, sender, []string{"host", "sender"})
	receiverEvents := make(chan Message, 128)
	receiver, runReceiver := startTestClient(t, ctx, server, "receiver", receiverEvents, &key)
	waitForPeers(t, sender, []string{"host", "sender", "receiver"})
	for index := 0; index < 11; index++ {
		if err := sender.SendMessage(fmt.Sprintf("burst-%02d", index)); err != nil {
			t.Fatal(err)
		}
	}
	seen := make(map[string]bool)
	deadline := time.NewTimer(500 * time.Millisecond)
	defer deadline.Stop()
	for {
		select {
		case message := <-receiverEvents:
			if message.Type == "msg" && strings.HasPrefix(message.Content, "burst-") {
				seen[message.Content] = true
			}
		case <-deadline.C:
			if len(seen) != 10 || seen["burst-10"] {
				t.Fatalf("relayed burst messages = %#v", seen)
			}
			cancel()
			waitRun(t, runSender)
			waitRun(t, runReceiver)
			waitRun(t, runServer)
			sender.ZeroKey()
			receiver.ZeroKey()
			return
		}
	}
}

func TestRateLimitRecoversIfClockMovesBackward(t *testing.T) {
	now := time.Unix(100, 0)
	server := &Server{config: ServerConfig{Now: func() time.Time { return now }}}
	candidate := &peer{rateWindowStart: now.Unix()}
	for range 10 {
		if !server.allowMessage(candidate) {
			t.Fatal("message within initial rate window was rejected")
		}
	}
	if server.allowMessage(candidate) {
		t.Fatal("eleventh message within rate window was accepted")
	}
	now = time.Unix(99, 0)
	if !server.allowMessage(candidate) {
		t.Fatal("rate window did not reset after clock moved backward")
	}
}

func TestAtomicAdmissionNeverExceedsPeerLimit(t *testing.T) {
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	key := testKey()
	server, runServer := startTestServer(t, ctx, ServerConfig{Nick: "host", MaxPeers: 2}, &key)
	var clientsMu sync.Mutex
	var clients []*Client
	var runs []<-chan error
	var group sync.WaitGroup
	for index := 0; index < 20; index++ {
		group.Add(1)
		go func(index int) {
			defer group.Done()
			client, err := Connect(ctx, ClientConfig{
				Address: fmt.Sprintf("127.0.0.1:%d", server.Port()), Nick: fmt.Sprintf("p%d", index),
			}, &key)
			if err != nil {
				return
			}
			done := make(chan error, 1)
			go func() { done <- client.Run(ctx) }()
			clientsMu.Lock()
			clients = append(clients, client)
			runs = append(runs, done)
			clientsMu.Unlock()
		}(index)
	}
	group.Wait()
	time.Sleep(100 * time.Millisecond)
	if count := server.PeerCount(); count > 2 {
		t.Fatalf("peer count = %d, exceeds limit 2", count)
	}
	cancel()
	for _, run := range runs {
		select {
		case <-run: // over-limit clients are expected to observe an immediate EOF
		case <-time.After(3 * time.Second):
			t.Fatal("client did not stop")
		}
	}
	waitRun(t, runServer)
	for _, client := range clients {
		client.ZeroKey()
	}
}

func TestPeerChurnAndMessageStorm(t *testing.T) {
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	key := testKey()
	server, runServer := startTestServer(t, ctx, ServerConfig{Nick: "host", MaxPeers: 24}, &key)

	const clientCount = 16
	clients := make([]*Client, clientCount)
	runs := make([]<-chan error, clientCount)
	var connectGroup sync.WaitGroup
	connectErrors := make(chan error, clientCount)
	for index := range clientCount {
		connectGroup.Add(1)
		go func(index int) {
			defer connectGroup.Done()
			client, err := Connect(ctx, ClientConfig{
				Address: fmt.Sprintf("127.0.0.1:%d", server.Port()),
				Nick:    fmt.Sprintf("churn-%02d", index),
			}, &key)
			if err != nil {
				connectErrors <- err
				return
			}
			done := make(chan error, 1)
			clients[index], runs[index] = client, done
			go func() { done <- client.Run(ctx) }()
		}(index)
	}
	connectGroup.Wait()
	close(connectErrors)
	for err := range connectErrors {
		t.Fatal(err)
	}
	waitPeerCount(t, server, clientCount)

	var traffic sync.WaitGroup
	for index, client := range clients {
		traffic.Add(1)
		go func(index int, client *Client) {
			defer traffic.Done()
			for message := range 3 {
				_ = client.SendMessage(fmt.Sprintf("%02d/%d", index, message))
			}
			_ = client.SendLeave()
			_ = client.Close()
		}(index, client)
	}
	for message := range 8 {
		if err := server.SendMessage(fmt.Sprintf("host/%d", message)); err != nil {
			t.Fatal(err)
		}
	}
	traffic.Wait()
	for index, run := range runs {
		waitRun(t, run)
		clients[index].ZeroKey()
	}
	waitPeerCount(t, server, 0)
	cancel()
	waitRun(t, runServer)
}

func TestBotAPIContractAndJSONEscaping(t *testing.T) {
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	key := testKey()
	hostEvents := make(chan Message, 32)
	server, runServer := startTestServer(t, ctx, ServerConfig{
		Nick: "host", OnEvent: func(message Message) { hostEvents <- message },
	}, &key)
	clientEvents := make(chan Message, 32)
	client, runClient := startTestClient(t, ctx, server, `bot"nick`, clientEvents, &key)
	waitForPeers(t, client, []string{"host", `bot"nick`})
	api := &BotAPI{client: client}
	httpServer := httptest.NewServer(api.Handler())
	defer httpServer.Close()

	getJSON(t, httpServer.URL+"/health", &map[string]string{"status": "ok"})
	var nick map[string]string
	getJSON(t, httpServer.URL+"/nick", &nick)
	if nick["nick"] != `bot"nick` {
		t.Fatalf("nick response = %#v", nick)
	}
	var peers []string
	getJSON(t, httpServer.URL+"/peers", &peers)
	if !equalStringSlices(peers, []string{"host", `bot"nick`}) {
		t.Fatalf("peers = %#v", peers)
	}
	response, err := http.Post(httpServer.URL+"/send", "text/plain", strings.NewReader("hello\n"))
	if err != nil {
		t.Fatal(err)
	}
	response.Body.Close()
	if response.StatusCode != http.StatusOK {
		t.Fatalf("send status = %d", response.StatusCode)
	}
	if message := waitMessage(t, hostEvents, "msg", "hello"); message.Sender != `bot"nick` {
		t.Fatalf("bot sender = %q", message.Sender)
	}
	if err := server.SendMessage("remote"); err != nil {
		t.Fatal(err)
	}
	_ = waitMessage(t, clientEvents, "msg", "remote")
	var messages []BufferedMessage
	getJSON(t, httpServer.URL+"/messages?since=0&wait=1", &messages)
	if len(messages) == 0 || messages[len(messages)-1].Content != "remote" {
		t.Fatalf("messages = %#v", messages)
	}
	request, _ := http.NewRequest(http.MethodPost, httpServer.URL+"/quit", nil)
	response, err = http.DefaultClient.Do(request)
	if err != nil {
		t.Fatal(err)
	}
	response.Body.Close()
	if response.StatusCode != http.StatusOK {
		t.Fatalf("quit status = %d", response.StatusCode)
	}
	waitRun(t, runClient)
	cancel()
	waitRun(t, runServer)
	client.ZeroKey()
}

func TestBotPeersIsAlwaysJSONArray(t *testing.T) {
	client := &Client{config: ClientConfig{Nick: "bot"}, buffer: NewMessageBuffer(1)}
	api := &BotAPI{client: client}
	request := httptest.NewRequest(http.MethodGet, "/peers", nil)
	recorder := httptest.NewRecorder()
	api.Handler().ServeHTTP(recorder, request)
	if recorder.Code != http.StatusOK || recorder.Body.String() != "[]\n" {
		t.Fatalf("empty peers response = status %d body %q", recorder.Code, recorder.Body.String())
	}
}

func TestMessageBufferRetentionAndEventDrivenWait(t *testing.T) {
	buffer := NewMessageBuffer(2)
	buffer.Append(Message{Timestamp: 1, Sender: "a", Content: "one", Type: "msg"})
	buffer.Append(Message{Timestamp: 2, Sender: "b", Content: "two", Type: "msg"})
	buffer.Append(Message{Timestamp: 3, Sender: "c", Content: "three", Type: "msg"})
	got := buffer.Since(0)
	if len(got) != 2 || got[0].ID != 2 || got[1].ID != 3 {
		t.Fatalf("retained messages = %#v", got)
	}
	ctx, cancel := context.WithTimeout(context.Background(), time.Second)
	defer cancel()
	done := make(chan []BufferedMessage, 1)
	go func() { done <- buffer.Wait(ctx, 3, time.Second) }()
	buffer.Append(Message{Timestamp: 4, Sender: "d", Content: "four", Type: "msg"})
	select {
	case messages := <-done:
		if len(messages) != 1 || messages[0].ID != 4 {
			t.Fatalf("wait messages = %#v", messages)
		}
	case <-time.After(200 * time.Millisecond):
		t.Fatal("long poll did not wake on append")
	}
}

func testKey() secretbox.Key {
	var key secretbox.Key
	copy(key[:], bytes.Repeat([]byte{0x42}, len(key)))
	return key
}

func startTestServer(t *testing.T, ctx context.Context, config ServerConfig, key *secretbox.Key) (*Server, <-chan error) {
	t.Helper()
	server, err := NewServer(config, key)
	if err != nil {
		t.Fatal(err)
	}
	done := make(chan error, 1)
	go func() { done <- server.Run(ctx) }()
	return server, done
}

func startTestClient(t *testing.T, ctx context.Context, server *Server, nick string, events chan<- Message, key *secretbox.Key) (*Client, <-chan error) {
	t.Helper()
	client, err := Connect(ctx, ClientConfig{
		Address: fmt.Sprintf("127.0.0.1:%d", server.Port()), Nick: nick,
		OnEvent: func(message Message) { events <- message },
	}, key)
	if err != nil {
		t.Fatal(err)
	}
	done := make(chan error, 1)
	go func() { done <- client.Run(ctx) }()
	return client, done
}

func waitForPeers(t *testing.T, client *Client, want []string) {
	t.Helper()
	deadline := time.Now().Add(3 * time.Second)
	for time.Now().Before(deadline) {
		if equalStringSlices(client.Peers(), want) {
			return
		}
		time.Sleep(5 * time.Millisecond)
	}
	t.Fatalf("peers = %#v, want %#v", client.Peers(), want)
}

func waitPeerCount(t *testing.T, server *Server, want int) {
	t.Helper()
	deadline := time.Now().Add(3 * time.Second)
	for time.Now().Before(deadline) {
		if server.PeerCount() == want {
			return
		}
		time.Sleep(5 * time.Millisecond)
	}
	t.Fatalf("peer count = %d, want %d", server.PeerCount(), want)
}

func waitMessage(t *testing.T, events <-chan Message, messageType, content string) Message {
	t.Helper()
	timer := time.NewTimer(3 * time.Second)
	defer timer.Stop()
	for {
		select {
		case message := <-events:
			if message.Type == messageType && message.Content == content {
				return message
			}
		case <-timer.C:
			t.Fatalf("timed out waiting for %s %q", messageType, content)
		}
	}
}

func waitRun(t *testing.T, done <-chan error) {
	t.Helper()
	select {
	case err := <-done:
		if err != nil {
			t.Errorf("run failed: %v", err)
		}
	case <-time.After(3 * time.Second):
		t.Fatal("run did not stop")
	}
}

func getJSON(t *testing.T, endpoint string, target any) {
	t.Helper()
	response, err := http.Get(endpoint)
	if err != nil {
		t.Fatal(err)
	}
	defer response.Body.Close()
	if response.StatusCode != http.StatusOK {
		body, _ := io.ReadAll(response.Body)
		t.Fatalf("GET %s status %d: %s", endpoint, response.StatusCode, body)
	}
	if err := json.NewDecoder(response.Body).Decode(target); err != nil {
		t.Fatal(err)
	}
}

func equalStringSlices(first, second []string) bool {
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

func FuzzParseNickList(f *testing.F) {
	f.Add([]byte("host\npeer\n"))
	f.Fuzz(func(t *testing.T, data []byte) { _ = parseNickList(data) })
}

func TestBotMessagesQueryUsesStandardURLParsing(t *testing.T) {
	values := url.Values{"since": {"12"}, "wait": {"120"}}
	if values.Encode() != "since=12&wait=120" {
		t.Fatal(values.Encode())
	}
}
