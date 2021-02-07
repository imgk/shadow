package resolver

import (
	"context"
	"errors"
	"fmt"
	"net"
	"net/url"
	"strings"
	"time"

	"github.com/imgk/shadow/pkg/resolver/http"
	"github.com/imgk/shadow/pkg/resolver/tcp"
	"github.com/imgk/shadow/pkg/resolver/tls"
	"github.com/imgk/shadow/pkg/resolver/udp"
)

// Resolver is ...
type Resolver interface {
	// Resolve is ...
	// resolve dns query in byte slice and store answers to the incoming byte slice
	// for compatible reason, the first 2 bytes are reserved for length space for
	// dns over tcp and dns over tls, the input length is the length of dns message
	// without 2 prefix bytes, and the output length also does not include the prefix bytes
	Resolve([]byte, int) (int, error)
	// DialContext is ...
	// net.Resovler.Dial
	DialContext(context.Context, string, string) (net.Conn, error)
}

// NewResolver is ...
func NewResolver(s string) (Resolver, error) {
	u, err := url.Parse(s)
	if err != nil {
		return nil, fmt.Errorf("parse url %v error: %w", s, err)
	}

	switch u.Scheme {
	case "udp":
		addr, err := net.ResolveUDPAddr("udp", u.Host)
		if err != nil {
			return nil, err
		}

		resolver := &udp.Resolver{
			Addr:    addr.String(),
			Timeout: time.Second * 3,
		}
		return resolver, nil
	case "tcp":
		addr, err := net.ResolveTCPAddr("tcp", u.Host)
		if err != nil {
			return nil, err
		}

		resolver := &tcp.Resolver{
			Addr:    addr.String(),
			Timeout: time.Second * 3,
		}
		return resolver, nil
	case "tls":
		addr, err := net.ResolveTCPAddr("tcp", u.Host)
		if err != nil {
			return nil, err
		}

		domain, _, err := net.SplitHostPort(u.Host)
		if err != nil {
			return nil, err
		}
		if u.Fragment != "" {
			domain = u.Fragment
		}
		resolver := tls.NewResolver(addr.String(), domain)
		return resolver, nil
	case "https":
		addr, err := net.ResolveTCPAddr("tcp", u.Host)
		if err != nil {
			return nil, err
		}

		domain, _, err := net.SplitHostPort(u.Host)
		if err != nil {
			return nil, err
		}
		if u.Fragment != "" {
			domain = u.Fragment
			s = strings.TrimSuffix(s, fmt.Sprintf("#%s", domain))
		}
		resolver := http.NewResolver(s, addr.String(), domain, "POST")
		return resolver, nil
	default:
		return nil, errors.New("invalid dns protocol")
	}
}
