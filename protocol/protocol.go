package protocol

import (
	"errors"
	"strings"
	"time"

	"github.com/imgk/shadow/common"
)

var errNotProtocol = errors.New("not a supported scheme")

var handlers = map[string](func(string, time.Duration) (common.Handler, error)){}

func RegisterHandler(proto string, fn func(string, time.Duration) (common.Handler, error)) {
	handlers[proto] = fn
}

func NewHandler(url string, timeout time.Duration) (common.Handler, error) {
	for proto, fn := range handlers {
		if strings.HasPrefix(url, proto) {
			return fn(url, timeout)
		}
	}
	return nil, errNotProtocol
}
