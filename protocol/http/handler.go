package http

import (
	"bufio"
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

var errNotSupport = errors.New("http proxy does not support UDP")

type CodeError int

func (e CodeError) Error() string {
	return fmt.Sprintf("http response code error: %v", int(e))
}

type Dialer interface {
	Dial() (net.Conn, error)
}

type rawDialer struct {
	addr string
}

func (d rawDialer) Dial() (net.Conn, error) {
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

func (d tlsDialer) Dial() (net.Conn, error) {
	conn, err := net.Dial("tcp", d.addr)
	if err != nil {
		return nil, err
	}
	if nc, ok := conn.(*net.TCPConn); ok {
		nc.SetKeepAlive(true)
	}

	conn = tls.Client(conn, d.config.Clone())
	if err := conn.(*tls.Conn).Handshake(); err != nil {
		conn.Close()
		return nil, err
	}
	return conn, nil
}

type Handler struct {
	readers sync.Pool
	dialer  Dialer
	auth    string
}

func NewHandler(s string, timeout time.Duration) (*Handler, error) {
	auth, addr, domain, https, err := ParseUrl(s)
	if err != nil {
		return nil, err
	}
	if auth != "" {
		auth = fmt.Sprintf("Basic %v", base64.StdEncoding.EncodeToString([]byte(auth)))
	}

	handler := &Handler{auth: auth}
	handler.readers = sync.Pool{
		New: func() interface{} {
			return bufio.NewReader(nil)
		},
	}
	if https {
		handler.dialer = tlsDialer{
			addr: addr,
			config: tls.Config{
				ServerName:         domain,
				ClientSessionCache: tls.NewLRUClientSessionCache(32),
				InsecureSkipVerify: false,
			},
		}
	} else {
		handler.dialer = rawDialer{addr: addr}
	}

	return handler, nil
}

func (h *Handler) Dial(addr string) (conn net.Conn, err error) {
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
	if er := req.Write(conn); er != nil {
		err = er
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
		err = CodeError(res.StatusCode)
		return
	}

	return
}

func (*Handler) Close() error {
	return nil
}

func (h *Handler) Handle(conn net.Conn, tgt net.Addr) error {
	defer conn.Close()

	rc, err := h.Dial(tgt.String())
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

func (*Handler) HandlePacket(conn common.PacketConn) error {
	return errNotSupport
}
