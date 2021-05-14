package resolver

import (
	"context"
	"errors"
	"net"
)

type metaResolver struct {
	servers []Resolver
}

// FallbackResolver is ...
type FallbackResolver metaResolver

// Resolve is ...
func (r *FallbackResolver) Resolve(b []byte, l int) (n int, err error) {
	for _, s := range r.servers {
		n, err = s.Resolve(b, l)
		if err == nil {
			return
		}
	}
	return 0, errors.New("no server available")
}

// DialContext is ...
func (r *FallbackResolver) DialContext(ctx context.Context, network, addr string) (conn net.Conn, err error) {
	for _, s := range r.servers {
		conn, err = s.DialContext(ctx, network, addr)
		if err == nil {
			return
		}
	}
	return nil, errors.New("no server available")
}

var _ Resolver = (*FallbackResolver)(nil)
