package resolver

import (
	"context"
	"crypto/tls"
	"fmt"
	"net"
	"net/http"
	"net/url"
	"strings"
	"time"

	"github.com/imgk/shadow/pkg/resolver/udp"
	"github.com/imgk/shadow/pkg/resolver/tcp"
	tlsdns "github.com/imgk/shadow/pkg/resolver/tls"
	httpdns "github.com/imgk/shadow/pkg/resolver/http"
)

// Resolver is ...
type Resolver interface {
	Resolve([]byte, int) (int, error)
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
		resolver := &tlsdns.Resolver{
			Addr: addr.String(),
			Config: tls.Config{
				ServerName:         domain,
				ClientSessionCache: tls.NewLRUClientSessionCache(32),
				InsecureSkipVerify: false,
			},
			Timeout: time.Second * 3,
		}
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
		}
		resolver := httpdns.NewResolver(strings.TrimSuffix(s, fmt.Sprintf("#%s", domain)), addr.String(), domain, http.MethodPost)
		resolver.Client.Transport = &http.Transport{
			Dial:              resolver.Dialer.Dial,
			DialContext:       resolver.Dialer.DialContext,
			TLSClientConfig:   &resolver.Dialer.Config,
			DialTLS:           resolver.Dialer.DialTLS,
			DialTLSContext:    resolver.Dialer.DialTLSContext,
			ForceAttemptHTTP2: true,
		}
		return resolver, nil
	default:
		return nil, fmt.Errorf("invalid dns protocol")
	}
}
