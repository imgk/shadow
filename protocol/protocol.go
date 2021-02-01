package protocol

import (
	"errors"
	"fmt"
	"strings"
	"time"

	"github.com/imgk/shadow/pkg/gonet"
)

// handlers is to store all NewHandlerFunc
var handlers = map[string]NewHandlerFunc{}

// NewHandlerFunc is ...
type NewHandlerFunc func(string, time.Duration) (gonet.Handler, error)

// RegisterHandler is ...
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
	return nil, errors.New(fmt.Sprintf("not a supported scheme: %v", url))
}
