package protocol

import (
	"errors"
	"net/url"
	"time"

	"github.com/imgk/shadow/netstack"
	"github.com/imgk/shadow/protocol/balancer"
	"github.com/imgk/shadow/protocol/shadowsocks"
	"github.com/imgk/shadow/protocol/socks"
	"github.com/imgk/shadow/protocol/trojan"
)

func NewHandler(s []string, timeout time.Duration) (netstack.Handler, error) {
	if len(s) == 1 {
		return PickHandler(s[0], timeout)
	}

	handler := make([]netstack.Handler, len(s))
	for i, server := range s {
		h, err := PickHandler(server, timeout)
		if err != nil {
			return nil, err
		}

		handler[i] = h
	}

	return balancer.NewHandler(handler), nil
}

func PickHandler(s string, timeout time.Duration) (netstack.Handler, error) {
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
