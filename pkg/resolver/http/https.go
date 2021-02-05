package http

import (
	"bytes"
	"context"
	"crypto/tls"
	"encoding/base64"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"time"
)

var (
	_ net.Conn       = (*Conn)(nil)
	_ net.PacketConn = (*Conn)(nil)
)

// Resolver is ...
type Resolver struct {
	// Dialer is ...
	Dialer NetDialer
	// BaseURL is ...
	BaseURL string
	// Timeout is ...
	Timeout time.Duration
	// Client is ...
	Client http.Client
	// SendRequest is ...
	SendRequest func(*http.Client, string, []byte, int) (int, error)
}

// NewResolver is ...
func NewResolver(baseURL, addr, domain, method string) *Resolver {
	resolver := &Resolver{
		Dialer: NetDialer{
			Dialer: net.Dialer{},
			Addr:   addr,
			Config: tls.Config{
				ServerName:         domain,
				ClientSessionCache: tls.NewLRUClientSessionCache(32),
			},
		},
		BaseURL: baseURL,
		Timeout: time.Second * 3,
		Client: http.Client{
			Timeout: time.Second * 3,
		},
	}
	switch method {
	case http.MethodPost:
		resolver.SendRequest = Post
	case http.MethodGet:
		resolver.SendRequest = Get
	}
	return resolver
}

// Resolve is ...
func (r *Resolver) Resolve(b []byte, n int) (int, error) {
	return r.SendRequest(&r.Client, r.BaseURL, b, n)
}

// DialContext is ...
func (r *Resolver) DialContext(ctx context.Context, network, address string) (net.Conn, error) {
	return NewConn(r), nil
}

// Post is ...
func Post(r *http.Client, baseURL string, b []byte, n int) (int, error) {
	req, err := http.NewRequest(http.MethodPost, baseURL, bytes.NewBuffer(b[2:2+n]))
	if err != nil {
		return 0, err
	}
	req.Header.Add("accept", "application/dns-message")
	req.Header.Add("content-type", "application/dns-message")

	res, err := r.Do(req)
	if err != nil {
		return 0, err
	}
	defer res.Body.Close()

	if res.StatusCode != http.StatusOK {
		return 0, fmt.Errorf("bad http response code: %v", res.StatusCode)
	}

	nr, err := Buffer(b[2:]).ReadFrom(res.Body)
	return int(nr), err
}

// Get is ...
func Get(r *http.Client, baseURL string, b []byte, n int) (int, error) {
	req, err := http.NewRequest(http.MethodGet, fmt.Sprintf("%s?%s=%s", baseURL, "dns", base64.RawURLEncoding.EncodeToString(b[2:2+n])), nil)
	if err != nil {
		return 0, err
	}
	req.Header.Add("accept", "application/dns-message")
	req.Header.Add("content-type", "application/dns-message")

	res, err := r.Do(req)
	if err != nil {
		return 0, err
	}
	defer res.Body.Close()

	if res.StatusCode != http.StatusOK {
		return 0, fmt.Errorf("bad http response code: %v", res.StatusCode)
	}

	nr, err := Buffer(b[2:]).ReadFrom(res.Body)
	return int(nr), err
}

// Conn is ...
type Conn struct {
	// Resolver is ...
	Resolver *Resolver

	reader *bytes.Reader
	buff   []byte
}

// NewConn is ...
func NewConn(r *Resolver) *Conn {
	c := &Conn{
		Resolver: r,
		reader:   bytes.NewReader(nil),
		buff:     make([]byte, 4<<10),
	}
	return c
}

func (c *Conn) Close() error                       { return nil }
func (c *Conn) LocalAddr() net.Addr                { return nil }
func (c *Conn) RemoteAddr() net.Addr               { return nil }
func (c *Conn) SetDeadline(t time.Time) error      { return nil }
func (c *Conn) SetReadDeadline(t time.Time) error  { return nil }
func (c *Conn) SetWriteDeadline(t time.Time) error { return nil }

// Write is ...
func (c *Conn) Write(b []byte) (int, error) {
	return c.WriteTo(b, nil)
}

// WriteTo is ...
func (c *Conn) WriteTo(b []byte, addr net.Addr) (int, error) {
	n := copy(c.buff[2:], b)
	n, err := c.Resolver.Resolve(c.buff, n)
	c.reader.Reset(c.buff[2 : 2+n])
	return len(b), err
}

// Read is ...
func (c *Conn) Read(b []byte) (int, error) {
	n, _, err := c.ReadFrom(b)
	return n, err
}

// ReadFrom is ...
func (c *Conn) ReadFrom(b []byte) (int, net.Addr, error) {
	n, err := Buffer(b).ReadFrom(c.reader)
	return int(n), nil, err
}

// Buffer is ...
type Buffer []byte

// ReadFrom is ...
func (b Buffer) ReadFrom(r io.Reader) (n int64, err error) {
	for {
		nr, er := r.Read(b[n:])
		if nr > 0 {
			n += int64(nr)
		}
		if er != nil {
			if errors.Is(er, io.EOF) {
				break
			}
			err = er
			break
		}
		if int(n) == len(b) {
			err = io.ErrShortBuffer
			break
		}
	}
	return
}
