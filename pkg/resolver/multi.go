package resolver

import (
	"context"
	"errors"
	"net"
)

type metaResolver struct {
	servers []Resolver
}

// Type is ...
type Type int

const (
	// Fallback is ...
	Fallback Type = iota
)

// NewMultiResolver is ...
func NewMultiResolver(ss []string, t Type) (Resolver, error) {
	if len(ss) == 0 {
		return nil, errors.New("zero length name server")
	}

	if len(ss) == 1 {
		return NewResolver(ss[0])
	}

	rr := []Resolver{}
	for _, s := range ss {
		r, err := NewResolver(s)
		if err != nil {
			return nil, err
		}
		rr = append(rr, r)
	}

	switch t {
	case Fallback:
		return &FallbackResolver{servers: rr}, nil
	}
	return nil, errors.New("type error")
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
