package proto

import (
	"fmt"
	"strings"
	"time"

	"github.com/imgk/shadow/pkg/gonet"
)

// handlers is to store all NewHandlerFunc
var handlers = map[string]NewHandlerFunc{}

// NewHandlerFunc is ...
// give a handler for a protocol scheme
type NewHandlerFunc func(string, time.Duration) (gonet.Handler, error)

// RegisterHandler is ...
// register a new protocol scheme
func RegisterHandler(proto string, fn NewHandlerFunc) {
	handlers[proto] = fn
}

// NewHandler is ...
func NewHandler(url string, timeout time.Duration) (gonet.Handler, error) {
	ss := strings.Split(url, ":")
	fn, ok := handlers[ss[0]]
	if ok {
		return fn(url, timeout)
	}
	return nil, fmt.Errorf("not a supported scheme: %v", url)
}
