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

	"github.com/imgk/shadow/netstack"
	"github.com/imgk/shadow/protocol"
)

func init() {
	protocol.RegisterHandler("http", func(s string, timeout time.Duration) (netstack.Handler, error) {
		return newHandler(s, timeout)
	})
	protocol.RegisterHandler("https", func(s string, timeout time.Duration) (netstack.Handler, error) {
		return newHandler(s, timeout)
	})
	protocol.RegisterHandler("http2", func(s string, timeout time.Duration) (netstack.Handler, error) {
		return newH2Handler(s, timeout)
	})
	protocol.RegisterHandler("http3", func(s string, timeout time.Duration) (netstack.Handler, error) {
		return newH2Handler(s, timeout)
	})
}

// rawConn is ...
type rawConn struct {
	net.Conn
	Reader *bytes.Reader
}

// Read is ...
func (conn *rawConn) Read(b []byte) (int, error) {
	if conn.Reader == nil {
		return conn.Conn.Read(b)
	}
	n, err := conn.Reader.Read(b)
	if err != nil {
		if errors.Is(err, io.EOF) {
			conn.Reader = nil
			err = nil
		}
	}
	return n, err
}

// handler is ...
type handler struct {
	// Dial is to dial new net.TCPConn or tls.Conn
	Dial func(string, string) (net.Conn, error)

	proxyAuth string
}

// NewHandler is ...
func newHandler(s string, timeout time.Duration) (*handler, error) {
	auth, server, domain, scheme, err := ParseURL(s)
	if err != nil {
		return nil, err
	}

	handler := &handler{
		proxyAuth: auth,
	}
	switch scheme {
	case "http":
		handler.Dial = func(network, addr string) (net.Conn, error) {
			return net.Dial(network, server)
		}
	case "https":
		cfg := &tls.Config{
			ServerName:         domain,
			ClientSessionCache: tls.NewLRUClientSessionCache(32),
		}
		handler.Dial = func(network, addr string) (net.Conn, error) {
			conn, err := net.Dial("tcp", server)
			if err != nil {
				return nil, err
			}
			if nc, ok := conn.(*net.TCPConn); ok {
				nc.SetKeepAlive(true)
			}
			conn = tls.Client(conn, cfg)
			if err := conn.(*tls.Conn).Handshake(); err != nil {
				conn.Close()
				return nil, err
			}
			return conn, nil
		}
	}

	return handler, nil
}

// Close is ...
func (*handler) Close() error {
	return nil
}

// Handle is ...
func (h *handler) Handle(conn net.Conn, tgt net.Addr) error {
	defer conn.Close()

	rc, err := func(network, addr string) (conn net.Conn, err error) {
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
		if h.proxyAuth != "" {
			req.Header.Add("Proxy-Authorization", h.proxyAuth)
		}
		err = req.Write(conn)
		if err != nil {
			return
		}

		reader := bufio.NewReader(conn)
		res, err := http.ReadResponse(reader, req)
		if err != nil {
			return
		}
		if res.StatusCode != http.StatusOK {
			err = errors.New(fmt.Sprintf("http response code error: %v", res.StatusCode))
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
	}("tcp", tgt.String())
	if err != nil {
		return err
	}
	defer rc.Close()

	if err := netstack.Relay(conn, rc); err != nil {
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
func (h *handler) HandlePacket(conn netstack.PacketConn) error {
	return errors.New("http proxy does not support UDP")
}
