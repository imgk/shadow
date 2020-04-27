package protocol

import (
	"errors"
	"net/url"
	"time"

	"github.com/imgk/shadow/netstack"
	"github.com/imgk/shadow/protocol/shadowsocks"
	"github.com/imgk/shadow/protocol/socks"
	"github.com/imgk/shadow/protocol/trojan"
)

func NewHandler(s string, timeout time.Duration) (netstack.Handler, error) {
	u, err := url.Parse(s)
	if err != nil {
		return nil, err
	}

	switch u.Scheme {
	case "ss":
		return shadowsocks.NewHandler(s, timeout)
	case "trojan":
		return trojan.NewHandler(s, timeout)
	case "socks":
		return socks.NewHandler(s, timeout)
	default:
		return nil, errors.New("not a supported scheme")
	}
}
