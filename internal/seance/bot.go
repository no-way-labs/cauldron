package seance

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/no-way-labs/cauldron/internal/frame"
)

const maxBotRequestBody = 8192

type BotAPI struct {
	client   *Client
	listener net.Listener
	server   *http.Server
	close    sync.Once
}

func NewBotAPI(client *Client, port uint16) (*BotAPI, error) {
	if client == nil {
		return nil, errors.New("seance: bot API requires a client")
	}
	listener, err := net.Listen("tcp", fmt.Sprintf("127.0.0.1:%d", port))
	if err != nil {
		return nil, err
	}
	api := &BotAPI{client: client, listener: listener}
	api.server = &http.Server{
		Handler: api.Handler(), ReadHeaderTimeout: 5 * time.Second,
		ReadTimeout: 10 * time.Second, WriteTimeout: 125 * time.Second,
		IdleTimeout: 30 * time.Second, MaxHeaderBytes: 8192,
	}
	return api, nil
}

func (api *BotAPI) Port() uint16 { return uint16(api.listener.Addr().(*net.TCPAddr).Port) }

func (api *BotAPI) Handler() http.Handler {
	mux := http.NewServeMux()
	mux.HandleFunc("/send", api.handleSend)
	mux.HandleFunc("/messages", api.handleMessages)
	mux.HandleFunc("/peers", api.handlePeers)
	mux.HandleFunc("/quit", api.handleQuit)
	mux.HandleFunc("/nick", api.handleNick)
	mux.HandleFunc("/health", api.handleHealth)
	return http.HandlerFunc(func(writer http.ResponseWriter, request *http.Request) {
		writer.Header().Set("X-Content-Type-Options", "nosniff")
		mux.ServeHTTP(writer, request)
	})
}

func (api *BotAPI) Run() error {
	err := api.server.Serve(api.listener)
	if errors.Is(err, http.ErrServerClosed) {
		return nil
	}
	return err
}

func (api *BotAPI) Close(ctx context.Context) error {
	var err error
	api.close.Do(func() { err = api.server.Shutdown(ctx) })
	return err
}

func (api *BotAPI) handleSend(writer http.ResponseWriter, request *http.Request) {
	if request.Method != http.MethodPost {
		http.NotFound(writer, request)
		return
	}
	request.Body = http.MaxBytesReader(writer, request.Body, maxBotRequestBody)
	body, err := io.ReadAll(request.Body)
	if err != nil || len(body) > frame.MaxPayloadLen {
		http.Error(writer, "Message too large", http.StatusRequestEntityTooLarge)
		return
	}
	trimmed := strings.TrimRight(string(body), "\n\r")
	if trimmed == "" {
		http.Error(writer, "Empty message", http.StatusBadRequest)
		return
	}
	if err := api.client.SendMessage(trimmed); err != nil {
		http.Error(writer, "Failed to send", http.StatusInternalServerError)
		return
	}
	writeJSON(writer, http.StatusOK, map[string]string{"status": "sent"})
}

func (api *BotAPI) handleMessages(writer http.ResponseWriter, request *http.Request) {
	if request.Method != http.MethodGet {
		http.NotFound(writer, request)
		return
	}
	since, _ := strconv.ParseUint(request.URL.Query().Get("since"), 10, 64)
	wait, _ := strconv.ParseUint(request.URL.Query().Get("wait"), 10, 64)
	if wait > 120 {
		wait = 120
	}
	messages := api.client.Messages().Wait(request.Context(), since, time.Duration(wait)*time.Second)
	writeJSON(writer, http.StatusOK, messages)
}

func (api *BotAPI) handlePeers(writer http.ResponseWriter, request *http.Request) {
	if request.Method != http.MethodGet {
		http.NotFound(writer, request)
		return
	}
	writeJSON(writer, http.StatusOK, api.client.Peers())
}

func (api *BotAPI) handleQuit(writer http.ResponseWriter, request *http.Request) {
	if request.Method != http.MethodPost {
		http.NotFound(writer, request)
		return
	}
	writeJSON(writer, http.StatusOK, map[string]string{"status": "disconnecting"})
	go func() {
		_ = api.client.SendLeave()
		_ = api.client.Close()
	}()
}

func (api *BotAPI) handleNick(writer http.ResponseWriter, request *http.Request) {
	if request.Method != http.MethodGet {
		http.NotFound(writer, request)
		return
	}
	writeJSON(writer, http.StatusOK, map[string]string{"nick": api.client.Nick()})
}

func (api *BotAPI) handleHealth(writer http.ResponseWriter, request *http.Request) {
	if request.Method != http.MethodGet {
		http.NotFound(writer, request)
		return
	}
	writeJSON(writer, http.StatusOK, map[string]string{"status": "ok"})
}

func writeJSON(writer http.ResponseWriter, status int, value any) {
	writer.Header().Set("Content-Type", "application/json")
	writer.WriteHeader(status)
	_ = json.NewEncoder(writer).Encode(value)
}
