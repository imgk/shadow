package protocol

import (
	"errors"
	"strings"
	"time"

	"github.com/imgk/shadow/pkg/gonet"
)

var handlers = map[string](func(string, time.Duration) (gonet.Handler, error)){}

// RegisterHandler is ...
func RegisterHandler(proto string, fn func(string, time.Duration) (gonet.Handler, error)) {
	handlers[proto] = fn
}

// NewHandler is ...
func NewHandler(url string, timeout time.Duration) (gonet.Handler, error) {
	ss := strings.Split(url, ":")
	factory, ok := handlers[ss[0]]
	if ok {
		return factory(url, timeout)
	}
	return nil, errors.New("not a supported scheme: " + url)
}
