package http

import (
	"bufio"
	"bytes"
	"crypto/tls"
	"encoding/base64"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"sync"
	"time"

	"github.com/imgk/shadow/common"
	"github.com/imgk/shadow/protocol"
)

func init() {
	protocol.RegisterHandler("http", func(s string, timeout time.Duration) (common.Handler, error) {
		return NewHandler(s, timeout)
	})
	protocol.RegisterHandler("https", func(s string, timeout time.Duration) (common.Handler, error) {
		return NewHandler(s, timeout)
	})
}

type codeError int

func (e codeError) Error() string {
	return fmt.Sprintf("http response code error: %v", int(e))
}

type Dialer interface {
	Dial() (net.Conn, error)
}

type netDialer struct {
	addr string
}

func (d *netDialer) Dial() (net.Conn, error) {
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

type Conn struct {
	net.Conn
	Reader *bytes.Reader
}

func (conn *Conn) Read(b []byte) (int, error) {
	if conn.Reader == nil {
		return conn.Conn.Read(b)
	}
	n, err := conn.Reader.Read(b)
	if err != nil {
		if errors.Is(err, io.EOF) {
			conn.Reader = nil
			return n, nil
		}
		return n, err
	}
	return n, nil
}

type Handler struct {
	dialer  Dialer
	readers sync.Pool
	auth    string
}

func NewHandler(s string, timeout time.Duration) (*Handler, error) {
	auth, addr, domain, scheme, err := ParseUrl(s)
	if err != nil {
		return nil, err
	}
	if auth != "" {
		auth = fmt.Sprintf("Basic %v", base64.StdEncoding.EncodeToString([]byte(auth)))
	}

	handler := &Handler{
		readers: sync.Pool{
			New: func() interface{} {
				return bufio.NewReader(nil)
			},
		},
		auth: auth,
	}
	switch scheme {
	case "http":
		dialer := &netDialer{addr: addr}
		handler.dialer = dialer
	case "https":
		dialer := &tlsDialer{
			addr: addr,
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

	reader := h.readers.Get().(*bufio.Reader)
	defer h.readers.Put(reader)

	reader.Reset(conn)
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

func (*Handler) Close() error {
	return nil
}

func (h *Handler) Handle(conn net.Conn, tgt net.Addr) error {
	defer conn.Close()

	rc, err := h.Dial("tcp", tgt.String())
	if err != nil {
		return err
	}
	defer rc.Close()

	if err := common.Relay(conn, rc); err != nil {
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

func (h *Handler) HandlePacket(conn common.PacketConn) error {
	return errors.New("http proxy does not support UDP")
}
