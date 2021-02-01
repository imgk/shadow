package http

import (
	"bufio"
	"bytes"
	"crypto/tls"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"time"

	"github.com/imgk/shadow/pkg/gonet"
	"github.com/imgk/shadow/protocol"
	"github.com/imgk/shadow/protocol/http/http2"
)

func init() {
	protocol.RegisterHandler("http", func(s string, timeout time.Duration) (gonet.Handler, error) {
		return NewHandler(s, timeout)
	})
	protocol.RegisterHandler("https", func(s string, timeout time.Duration) (gonet.Handler, error) {
		return NewHandler(s, timeout)
	})
	protocol.RegisterHandler("http2", func(s string, timeout time.Duration) (gonet.Handler, error) {
		return http2.NewHandler(s, timeout)
	})
	protocol.RegisterHandler("http3", func(s string, timeout time.Duration) (gonet.Handler, error) {
		return http2.NewHandler(s, timeout)
	})
}

// rawConn is ...
type rawConn struct {
	net.Conn
	Reader *bytes.Reader
}

// Read is ...
func (c *rawConn) Read(b []byte) (int, error) {
	if c.Reader == nil {
		return c.Conn.Read(b)
	}
	n, err := c.Reader.Read(b)
	if err != nil {
		if errors.Is(err, io.EOF) {
			c.Reader = nil
			err = nil
		}
	}
	return n, err
}

// Dialer is ...
type Dialer interface {
	// Dial is ...
	Dial(string, string) (net.Conn, error)
}

// NetDialer is ...
type NetDialer struct {
	// Dialer is ...
	Dialer net.Dialer
	// Addr is ...
	Addr string
}

// Dial is ...
func (d *NetDialer) Dial(network, addr string) (net.Conn, error) {
	return d.Dialer.Dial(network, d.Addr)
}

// TLSDialer is ...
type TLSDialer struct {
	// Dialer is ...
	Dialer net.Dialer
	// Config is ...
	Config tls.Config
	// Addr is ...
	Addr string
}

// DialTLS is ...
func (d *TLSDialer) Dial(network, addr string) (net.Conn, error) {
	conn, err := d.Dialer.Dial(network, d.Addr)
	if err != nil {
		return nil, err
	}
	conn = tls.Client(conn, &d.Config)
	return conn, nil
}

// Handler is ...
type Handler struct {
	// Dial is to dial new net.TCPConn or tls.Conn
	Dial func(string, string) (net.Conn, error)

	proxyAuth string
}

// NewHandler is ...
func NewHandler(s string, timeout time.Duration) (*Handler, error) {
	auth, server, domain, scheme, err := ParseURL(s)
	if err != nil {
		return nil, err
	}

	handler := &Handler{
		proxyAuth: auth,
	}
	switch scheme {
	case "http":
		dialer := &NetDialer{
			Addr: server,
		}
		handler.Dial = dialer.Dial
	case "https":
		dialer := &TLSDialer{
			Config: tls.Config{
				ServerName:         domain,
				ClientSessionCache: tls.NewLRUClientSessionCache(32),
			},
			Addr: server,
		}
		handler.Dial = dialer.Dial
	}

	return handler, nil
}

// Close is ...
func (*Handler) Close() error {
	return nil
}

// Handle is ...
func (h *Handler) Handle(conn net.Conn, tgt net.Addr) error {
	defer conn.Close()

	rc, err := func(network, addr, proxyAuth string) (conn net.Conn, err error) {
		conn, err = h.Dial(network, addr)
		if err != nil {
			return
		}
		defer func() {
			if err != nil {
				conn.Close()
			}
		}()

		req, err := http.NewRequest(http.MethodConnect, "", nil)
		if err != nil {
			return
		}
		req.Host = addr
		if proxyAuth != "" {
			req.Header.Add("Proxy-Authorization", proxyAuth)
		}
		err = req.Write(conn)
		if err != nil {
			return
		}

		reader := bufio.NewReader(conn)
		r, err := http.ReadResponse(reader, req)
		if err != nil {
			return
		}
		if r.StatusCode != http.StatusOK {
			err = errors.New(fmt.Sprintf("http response code error: %v", r.StatusCode))
			return
		}
		if n := reader.Buffered(); n > 0 {
			b := make([]byte, n)
			if _, err = io.ReadFull(conn, b); err != nil {
				return
			}
			conn = &rawConn{Conn: conn, Reader: bytes.NewReader(b)}
		}

		return
	}("tcp", tgt.String(), h.proxyAuth)
	if err != nil {
		return err
	}
	defer rc.Close()

	if err := gonet.Relay(conn, rc); err != nil {
		if ne := net.Error(nil); errors.As(err, &ne) {
			if ne.Timeout() {
				return nil
			}
		}
		if errors.Is(err, io.ErrClosedPipe) || errors.Is(err, io.EOF) {
			return nil
		}
		return fmt.Errorf("relay error: %w", err)
	}

	return nil
}

// HandlePacket is ...
func (h *Handler) HandlePacket(conn gonet.PacketConn) error {
	return errors.New("http proxy does not support UDP")
}
