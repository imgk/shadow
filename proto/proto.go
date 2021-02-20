package proto

import (
	"encoding/json"
	"fmt"
	"time"

	"github.com/imgk/shadow/pkg/gonet"
)

// handlers is to store all NewHandlerFunc
var handlers = map[string]NewHandlerFunc{}

// NewHandlerFunc is ...
// give a handler for a protocol scheme
type NewHandlerFunc func(json.RawMessage, time.Duration) (gonet.Handler, error)

// RegisterNewHandlerFunc is ...
// register a new protocol scheme
func RegisterNewHandlerFunc(proto string, fn NewHandlerFunc) {
	handlers[proto] = fn
}

// NewHandler is ...
func NewHandler(b json.RawMessage, timeout time.Duration) (gonet.Handler, error) {
	type Proto struct {
		Proto string `json:"protocol"`
	}
	proto := Proto{}
	if err := json.Unmarshal(b, &proto); err != nil {
		return nil, fmt.Errorf("unmarshal server protocol error: %w", err)
	}

	fn, ok := handlers[proto.Proto]
	if ok {
		return fn(b, timeout)
	}
	return nil, fmt.Errorf("not a supported scheme: %v", proto.Proto)
}
