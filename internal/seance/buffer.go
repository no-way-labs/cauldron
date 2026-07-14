package seance

import (
	"context"
	"sync"
	"time"
)

const DefaultMessageRetention = 10_000

type BufferedMessage struct {
	ID        uint64 `json:"id"`
	Timestamp uint64 `json:"timestamp"`
	Sender    string `json:"sender"`
	Content   string `json:"content"`
	Type      string `json:"type"`
}

// MessageBuffer retains the newest bounded set of bot-visible messages while
// IDs remain monotonically increasing. Dropping old entries never reuses IDs.
type MessageBuffer struct {
	mu        sync.Mutex
	messages  []BufferedMessage
	nextID    uint64
	retention int
	notify    chan struct{}
	closed    bool
}

func NewMessageBuffer(retention int) *MessageBuffer {
	return &MessageBuffer{nextID: 1, retention: retention, notify: make(chan struct{})}
}

func (buffer *MessageBuffer) Append(message Message) {
	buffer.mu.Lock()
	defer buffer.mu.Unlock()
	if buffer.closed {
		return
	}
	buffer.messages = append(buffer.messages, BufferedMessage{
		ID: buffer.nextID, Timestamp: message.Timestamp, Sender: message.Sender,
		Content: message.Content, Type: message.Type,
	})
	buffer.nextID++
	if excess := len(buffer.messages) - buffer.retention; excess > 0 {
		copy(buffer.messages, buffer.messages[excess:])
		buffer.messages = buffer.messages[:len(buffer.messages)-excess]
	}
	close(buffer.notify)
	buffer.notify = make(chan struct{})
}

func (buffer *MessageBuffer) Since(since uint64) []BufferedMessage {
	buffer.mu.Lock()
	defer buffer.mu.Unlock()
	return buffer.sinceLocked(since)
}

func (buffer *MessageBuffer) sinceLocked(since uint64) []BufferedMessage {
	result := make([]BufferedMessage, 0)
	for _, message := range buffer.messages {
		if message.ID > since {
			result = append(result, message)
		}
	}
	return result
}

func (buffer *MessageBuffer) Wait(ctx context.Context, since uint64, duration time.Duration) []BufferedMessage {
	if duration < 0 {
		duration = 0
	}
	deadline := time.NewTimer(duration)
	defer deadline.Stop()
	for {
		buffer.mu.Lock()
		messages := buffer.sinceLocked(since)
		if len(messages) > 0 || buffer.closed || duration == 0 {
			buffer.mu.Unlock()
			return messages
		}
		notify := buffer.notify
		buffer.mu.Unlock()
		select {
		case <-ctx.Done():
			return nil
		case <-deadline.C:
			return buffer.Since(since)
		case <-notify:
		}
	}
}

func (buffer *MessageBuffer) Close() {
	buffer.mu.Lock()
	defer buffer.mu.Unlock()
	if buffer.closed {
		return
	}
	buffer.closed = true
	close(buffer.notify)
}
