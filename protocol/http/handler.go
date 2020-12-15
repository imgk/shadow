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

type codeError int

func (e codeError) Error() string {
	return fmt.Sprintf("http response code error: %v", int(e))
}

type Newer interface {
	New() (net.Conn, error)
}

type rawNewer struct {
	addr string
}

func (d rawNewer) New() (net.Conn, error) {
	conn, err := net.Dial("tcp", d.addr)
	if err != nil {
		return nil, err
	}
	if nc, ok := conn.(*net.TCPConn); ok {
		nc.SetKeepAlive(true)
	}
	return conn, nil
}

type tlsNewer struct {
	addr   string
	config tls.Config
}

func (d *tlsNewer) New() (net.Conn, error) {
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
	Newer
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
		newer := rawNewer{addr: addr}
		handler.Newer = newer
	case "https":
		newer := &tlsNewer{
			addr: addr,
			config: tls.Config{
				ServerName:         domain,
				ClientSessionCache: tls.NewLRUClientSessionCache(32),
				InsecureSkipVerify: false,
			},
		}
		handler.Newer = newer
	}

	return handler, nil
}

func (h *Handler) Dial(network, addr string) (conn net.Conn, err error) {
	conn, err = h.Newer.New()
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
