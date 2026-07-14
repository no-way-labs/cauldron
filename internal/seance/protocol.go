// Package seance implements Cauldron's ephemeral encrypted chat protocol and
// loopback bot API.
package seance

const Magic = "SEANCE_HELLO"

const (
	MessageJoin     byte = 1
	MessageChat     byte = 2
	MessageLeave    byte = 3
	MessageAnnounce byte = 4
	MessageNickList byte = 5
)

func ValidMessageType(value byte) bool {
	switch value {
	case MessageJoin, MessageChat, MessageLeave, MessageAnnounce, MessageNickList:
		return true
	default:
		return false
	}
}

type Message struct {
	Timestamp uint64 `json:"timestamp"`
	Sender    string `json:"sender"`
	Content   string `json:"content"`
	Type      string `json:"type"`
}

type EventHandler func(Message)
