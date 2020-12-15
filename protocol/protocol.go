package protocol

import (
	"errors"
	"strings"
	"time"

	"github.com/imgk/shadow/common"
)

var handlers = map[string](func(string, time.Duration) (common.Handler, error)){}

func RegisterHandler(proto string, fn func(string, time.Duration) (common.Handler, error)) {
	handlers[proto] = fn
}

func NewHandler(url string, timeout time.Duration) (common.Handler, error) {
	ss := strings.Split(url, ":")
	factory, ok := handlers[ss[0]]
	if ok {
		return factory(url, timeout)
	}
	return nil, errors.New("not a supported scheme: " + url)
}
