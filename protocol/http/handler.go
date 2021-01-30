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
	"net/url"
	"time"

	"golang.org/x/net/http2"

	"github.com/lucas-clemente/quic-go"
	"github.com/lucas-clemente/quic-go/http3"

	"github.com/imgk/shadow/netstack"
	"github.com/imgk/shadow/protocol"
)

func init() {
	protocol.RegisterHandler("http", func(s string, timeout time.Duration) (netstack.Handler, error) {
		return NewHandler(s, timeout)
	})
	protocol.RegisterHandler("https", func(s string, timeout time.Duration) (netstack.Handler, error) {
		return NewHandler(s, timeout)
	})
	protocol.RegisterHandler("http2", func(s string, timeout time.Duration) (netstack.Handler, error) {
		return NewHandler(s, timeout)
	})
	protocol.RegisterHandler("http3", func(s string, timeout time.Duration) (netstack.Handler, error) {
		return NewHandler(s, timeout)
	})
}

type codeError int

func (e codeError) Error() string {
	return fmt.Sprintf("http response code error: %v", int(e))
}

// Dialer is ...
type Dialer interface {
	Dial() (net.Conn, error)
}

type rawDialer struct {
	addr string
}

func (d *rawDialer) Dial() (net.Conn, error) {
	conn, err := net.Dial("tcp", d.addr)
	if err != nil {
		return nil, err
	}
	if nc, ok := conn.(*net.TCPConn); ok {
		nc.SetKeepAlive(true)
	}
	return conn, nil
}

type tlsDialer struct {
	addr   string
	config tls.Config
}

func (d *tlsDialer) Dial() (net.Conn, error) {
	conn, err := net.Dial("tcp", d.addr)
	if err != nil {
		return nil, err
	}
	if nc, ok := conn.(*net.TCPConn); ok {
		nc.SetKeepAlive(true)
	}

	conn = tls.Client(conn, &d.config)
	if err := conn.(*tls.Conn).Handshake(); err != nil {
		conn.Close()
		return nil, err
	}
	return conn, nil
}

// Conn is ...
type Conn struct {
	net.Conn
	Reader *bytes.Reader
}

// Read is ...
func (conn *Conn) Read(b []byte) (int, error) {
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

// Handler is ...
type Handler struct {
	dialer Dialer
	auth   string
}

// NewHandler is ...
func NewHandler(s string, timeout time.Duration) (netstack.Handler, error) {
	auth, server, domain, scheme, err := ParseUrl(s)
	if err != nil {
		return nil, err
	}

	if scheme == "http2" {
		handler := &handler{
			NewRequest: func(addr string, body io.ReadCloser) *http.Request {
				r := &http.Request{
					Method: http.MethodConnect,
					Host:   addr,
					Body:   body,
					URL: &url.URL{
						Scheme: "https",
						Host:   addr,
					},
					Proto:      "HTTP/2",
					ProtoMajor: 2,
					ProtoMinor: 0,
					Header:     make(http.Header),
				}
				r.Header.Set("Accept-Encoding", "identity")
				r.Header.Add("Proxy-Authorization", auth)
				return r
			},
			Client: http.Client{
				Transport: &http2.Transport{
					DialTLS: func(network, addr string, cfg *tls.Config) (conn net.Conn, err error) {
						conn, err = net.Dial("tcp", server)
						if err != nil {
							return
						}
						conn = tls.Client(conn, cfg)
						return
					},
					TLSClientConfig: &tls.Config{
						ServerName:         domain,
						ClientSessionCache: tls.NewLRUClientSessionCache(32),
					},
				},
			},
			proxyAuth: auth,
		}
		return handler, nil
	}

	if scheme == "http3" {
		handler := &handler{
			NewRequest: func(addr string, body io.ReadCloser) *http.Request {
				r := &http.Request{
					Method: http.MethodConnect,
					Host:   addr,
					Body:   body,
					URL: &url.URL{
						Scheme: "https",
						Host:   addr,
					},
					Proto:      "HTTP/3",
					ProtoMajor: 3,
					ProtoMinor: 0,
					Header:     make(http.Header),
				}
				r.Header.Set("Accept-Encoding", "identity")
				r.Header.Add("Proxy-Authorization", auth)
				return r
			},
			Client: http.Client{
				Transport: &http3.RoundTripper{
					Dial: func(network, addr string, tlsCfg *tls.Config, cfg *quic.Config) (quic.EarlySession, error) {
						return quic.DialAddrEarly(server, tlsCfg, cfg)
					},
					TLSClientConfig: &tls.Config{
						ServerName:         domain,
						ClientSessionCache: tls.NewLRUClientSessionCache(32),
					},
					QuicConfig: &quic.Config{KeepAlive: true},
				},
			},
			proxyAuth: auth,
		}
		return handler, nil
	}

	handler := &Handler{
		auth: auth,
	}
	switch scheme {
	case "http":
		dialer := &rawDialer{addr: server}
		handler.dialer = dialer
	case "https":
		dialer := &tlsDialer{
			addr: server,
			config: tls.Config{
				ServerName:         domain,
				ClientSessionCache: tls.NewLRUClientSessionCache(32),
				InsecureSkipVerify: false,
			},
		}
		handler.dialer = dialer
	}

	return handler, nil
}

// Dial is ...
func (h *Handler) Dial(network, addr string) (conn net.Conn, err error) {
	conn, err = h.dialer.Dial()
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
	if h.auth != "" {
		req.Header.Add("Proxy-Authorization", h.auth)
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
		err = codeError(res.StatusCode)
		return
	}
	if n := reader.Buffered(); n > 0 {
		b := make([]byte, n)
		if _, err = io.ReadFull(conn, b); err != nil {
			return
		}
		conn = &Conn{Conn: conn, Reader: bytes.NewReader(b)}
	}

	return
}

// Close is ...
func (*Handler) Close() error {
	return nil
}

// Handle is ...
func (h *Handler) Handle(conn net.Conn, tgt net.Addr) error {
	defer conn.Close()

	rc, err := h.Dial("tcp", tgt.String())
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
func (h *Handler) HandlePacket(conn netstack.PacketConn) error {
	return errors.New("http proxy does not support UDP")
}
