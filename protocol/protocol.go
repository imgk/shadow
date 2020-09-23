package protocol

import (
	"errors"
	"net/url"
	"time"

	"github.com/imgk/shadow/common"
	"github.com/imgk/shadow/protocol/shadowsocks"
	"github.com/imgk/shadow/protocol/socks"
	"github.com/imgk/shadow/protocol/trojan"
)

var errNotProtocol = errors.New("not a supported scheme")

var handler = map[string](func(string, time.Duration) (common.Handler, error)){}

func init() {
	RegisterHandler("shadowsocks", func(s string, timeout time.Duration) (common.Handler, error) {
		return shadowsocks.NewHandler(s, timeout)
	})
	RegisterHandler("socks", func(s string, timeout time.Duration) (common.Handler, error) {
		return socks.NewHandler(s, timeout)
	})
	RegisterHandler("trojan", func(s string, timeout time.Duration) (common.Handler, error) {
		return trojan.NewHandler(s, timeout)
	})
}

func RegisterHandler(p string, fn func(string, time.Duration) (common.Handler, error)) {
	handler[p] = fn
}

func NewHandler(s string, timeout time.Duration) (common.Handler, error) {
	u, err := url.Parse(s)
	if err != nil {
		return nil, err
	}

	fn, ok := handler[u.Scheme]
	if ok {
		return fn(s, timeout)
	}

	return nil, errNotProtocol
}
