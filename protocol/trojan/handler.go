package trojan

import (
	"context"
	"crypto/sha256"
	"crypto/tls"
	"encoding/hex"
	"errors"
	"fmt"
	"io"
	"net"
	"os"
	"sync"
	"time"

	"github.com/gorilla/websocket"
	"github.com/xtaci/smux"

	"github.com/imgk/shadow/netstack"
	"github.com/imgk/shadow/pkg/socks"
	"github.com/imgk/shadow/protocol"
)

func init() {
	protocol.RegisterHandler("trojan", func(s string, timeout time.Duration) (netstack.Handler, error) {
		return NewHandler(s, timeout)
	})
	protocol.RegisterHandler("trojan-go", func(s string, timeout time.Duration) (netstack.Handler, error) {
		return NewHandler(s, timeout)
	})
}

const (
	// trojan header length
	HeaderLen = 56

	cmdConnect   = 1
	cmdAssocaite = 3
)

type dialer struct {
	net.Dialer
	addr string
}

func (d *dialer) Dial(network, addr string) (net.Conn, error) {
	conn, err := d.Dialer.Dial(network, d.addr)
	if nc, ok := conn.(*net.TCPConn); ok {
		nc.SetKeepAlive(true)
	}
	return conn, err
}

func (d *dialer) DialContext(ctx context.Context, network, addr string) (net.Conn, error) {
	conn, err := d.Dialer.DialContext(ctx, network, d.addr)
	if nc, ok := conn.(*net.TCPConn); ok {
		nc.SetKeepAlive(true)
	}
	return conn, err
}

type Connector interface {
	Connect() (net.Conn, error)
}

type TLS struct {
	dialer
	server string
	config *tls.Config
}

func (h *TLS) Connect() (conn net.Conn, err error) {
	conn, err = h.dialer.Dial("tcp", h.server)
	if err != nil {
		return
	}

	conn = tls.Client(conn, h.config.Clone())
	if err = conn.(*tls.Conn).Handshake(); err != nil {
		conn.Close()
	}
	return
}

type WebSocket struct {
	dialer websocket.Dialer
	addr   string
}

func (h *WebSocket) Connect() (conn net.Conn, err error) {
	wc, _, err := h.dialer.Dial(h.addr, nil)
	conn = &wsConn{Conn: wc, Reader: &emptyReader{}}
	return
}

type muxConfig struct {
	sync.Mutex
	config smux.Config
	max    int
	conns  map[*smux.Session]struct{}
}

type Handler struct {
	Connector
	mux        muxConfig
	muxEnabled bool

	header  [HeaderLen + 2 + 8 + 2]byte
	timeout time.Duration
	server  string
	ticker  *time.Ticker
	closed  chan struct{}
}

func NewHandler(url string, timeout time.Duration) (*Handler, error) {
	password, address, path, transport, muxEnabled, domainName, err := ParseUrl(url)
	if err != nil {
		return nil, err
	}

	addr, err := net.ResolveUDPAddr("udp", address)
	if err != nil {
		return nil, err
	}

	host := addr.String()
	hd := &Handler{
		timeout: timeout,
		server:  host,
	}
	tlsConfig := &tls.Config{
		ServerName:         domainName,
		ClientSessionCache: tls.NewLRUClientSessionCache(32),
		InsecureSkipVerify: false,
	}
	dialer := dialer{
		Dialer: net.Dialer{},
		addr:   host,
	}

	hash := sha256.Sum224([]byte(password))
	hex.Encode(hd.header[:HeaderLen], hash[:])
	hd.header[HeaderLen], hd.header[HeaderLen+1] = 0x0d, 0x0a

	switch transport {
	case "websocket":
		hd.Connector = &WebSocket{
			dialer: websocket.Dialer{
				NetDial:         dialer.Dial,
				NetDialContext:  dialer.DialContext,
				TLSClientConfig: tlsConfig,
			},
			addr: fmt.Sprintf("wss://%s%s", domainName, path),
		}
	case "tls":
		hd.Connector = &TLS{
			server: hd.server,
			dialer: dialer,
			config: tlsConfig,
		}
	}

	switch muxEnabled {
	case "off":
		hd.muxEnabled = false
	case "v1":
		hd.mux = muxConfig{
			Mutex: sync.Mutex{},
			config: smux.Config{
				Version:           1,
				KeepAliveInterval: 10 * time.Second,
				KeepAliveTimeout:  30 * time.Second,
				MaxFrameSize:      32768,
				MaxReceiveBuffer:  4194304,
				MaxStreamBuffer:   65536,
			},
			max:   8,
			conns: make(map[*smux.Session]struct{}),
		}

		copy(hd.header[HeaderLen+2:], []byte{0x7f, socks.AddrTypeIPv4, 0, 0, 0, 0, 0, 0, 0x0d, 0x0a})

		hd.muxEnabled = true
		hd.ticker = time.NewTicker(time.Minute * 3)
		hd.closed = make(chan struct{})
		go hd.closeIdleSession()
	case "v2":
		hd.mux = muxConfig{
			Mutex: sync.Mutex{},
			config: smux.Config{
				Version:           2,
				KeepAliveInterval: 10 * time.Second,
				KeepAliveTimeout:  30 * time.Second,
				MaxFrameSize:      32768,
				MaxReceiveBuffer:  4194304,
				MaxStreamBuffer:   65536,
			},
			max:   8,
			conns: make(map[*smux.Session]struct{}),
		}

		copy(hd.header[HeaderLen+2:], []byte{0x8f, socks.AddrTypeIPv4, 0, 0, 0, 0, 0, 0, 0x0d, 0x0a})

		hd.muxEnabled = true
		hd.ticker = time.NewTicker(time.Minute * 3)
		hd.closed = make(chan struct{})
		go hd.closeIdleSession()
	}

	return hd, nil
}

func (h *Handler) Close() error {
	if h.ticker != nil {
		h.ticker.Stop()
		close(h.closed)
	}
	return nil
}

func (h *Handler) closeIdleSession() {
LOOP:
	for {
		select {
		case <-h.ticker.C:
		case <-h.closed:
			break LOOP
		}

		h.mux.Lock()
		for sess, _ := range h.mux.conns {
			if sess.IsClosed() {
				delete(h.mux.conns, sess)
				continue
			}

			if sess.NumStreams() == 0 {
				sess.Close()
				delete(h.mux.conns, sess)
			}
		}
		h.mux.Unlock()
	}
}

func (h *Handler) ConnectMux() (conn net.Conn, err error) {
	h.mux.Lock()
	for sess, _ := range h.mux.conns {
		if sess.NumStreams() < h.mux.max {
			if sess.IsClosed() {
				delete(h.mux.conns, sess)
				continue
			}

			conn, err = sess.OpenStream()
			if err != nil {
				if errors.Is(err, smux.ErrGoAway) {
					go func(sess *smux.Session) {
						t := time.NewTicker(time.Minute)
						for range t.C {
							if sess.IsClosed() || sess.NumStreams() == 0 {
								sess.Close()
								t.Stop()
								return
							}
						}
					}(sess)
					delete(h.mux.conns, sess)
					continue
				}
				if sess.IsClosed() || sess.NumStreams() == 0 {
					delete(h.mux.conns, sess)
					continue
				}
			}

			h.mux.Unlock()
			return
		}
	}
	h.mux.Unlock()

	conn, err = h.ConnectMuxNew()
	return
}

func (h *Handler) ConnectMuxNew() (conn net.Conn, err error) {
	conn, err = h.Connect()
	if err != nil {
		return
	}

	defer func(conn net.Conn) {
		if err != nil {
			conn.Close()
		}
	}(conn)

	_, err = conn.Write(h.header[:])
	if err != nil {
		return
	}

	sess, err := smux.Client(conn, &h.mux.config)
	if err != nil {
		return
	}

	conn, err = sess.OpenStream()
	if err != nil {
		sess.Close()
		return
	}

	h.mux.Lock()
	h.mux.conns[sess] = struct{}{}
	h.mux.Unlock()

	return
}

func (h *Handler) DialConn(tgt net.Addr, cmd byte) (conn net.Conn, err error) {
	target := [HeaderLen + 2 + 1 + socks.MaxAddrLen + 2]byte{}

	conn, err = h.Connect()
	if err != nil {
		return
	}
	defer func() {
		if err != nil {
			conn.Close()
		}
	}()

	n := copy(target[0:], h.header[:HeaderLen+2])
	target[HeaderLen+2] = cmd

	addr, ok := tgt.(socks.Addr)
	if ok {
		copy(target[HeaderLen+2+1:], addr)
		n = HeaderLen + 2 + 1 + len(addr) + 2
	} else {
		addr, er := socks.ResolveAddrBuffer(tgt, target[HeaderLen+2+1:])
		if er != nil {
			err = fmt.Errorf("resolve addr error: %w", er)
			return
		}
		n = HeaderLen + 2 + 1 + len(addr) + 2
	}
	target[n-2], target[n-1] = 0x0d, 0x0a

	if _, er := conn.Write(target[:n]); er != nil {
		err = fmt.Errorf("write to server %v error: %w", h.server, er)
		return
	}

	return
}

func (h *Handler) DialMux(tgt net.Addr, cmd byte) (conn net.Conn, err error) {
	target := [HeaderLen + 2 + 1 + socks.MaxAddrLen + 2]byte{}

	conn, err = h.ConnectMux()
	if err != nil {
		return
	}
	defer func() {
		if err != nil {
			conn.Close()
		}
	}()

	target[0] = cmd
	n := 1

	addr, ok := tgt.(socks.Addr)
	if ok {
		n += copy(target[1:], addr)
	} else {
		addr, er := socks.ResolveAddrBuffer(tgt, target[1:])
		if er != nil {
			err = fmt.Errorf("resolve addr error: %w", er)
			return
		}
		n += len(addr)
	}

	if _, er := conn.Write(target[:n]); er != nil {
		err = fmt.Errorf("write to server %v error: %w", h.server, er)
		return
	}

	return
}

func (h *Handler) Dial(tgt net.Addr, cmd byte) (net.Conn, error) {
	if h.muxEnabled {
		return h.DialMux(tgt, cmd)
	}
	return h.DialConn(tgt, cmd)
}

func (h *Handler) Handle(conn net.Conn, tgt net.Addr) error {
	defer conn.Close()

	rc, err := h.Dial(tgt, cmdConnect)
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

func (h *Handler) HandlePacket(conn netstack.PacketConn) error {
	defer conn.Close()

	rc, err := h.Dial(conn.LocalAddr(), cmdAssocaite)
	if err != nil {
		return err
	}
	defer rc.Close()

	errCh := make(chan error, 1)
	go copyWithChannel(conn, rc, h.timeout, errCh)

	slice := netstack.Get()
	defer netstack.Put(slice)
	b := slice.Get()

	for {
		rc.SetReadDeadline(time.Now().Add(h.timeout))
		raddr, er := socks.ReadAddrBuffer(rc, b)
		if er != nil {
			if ne := net.Error(nil); errors.As(err, &ne) {
				if ne.Timeout() {
					break
				}
			}
			if errors.Is(er, smux.ErrTimeout) || errors.Is(er, io.ErrClosedPipe) || errors.Is(er, io.EOF) {
				break
			}
			err = fmt.Errorf("read addr error: %w", er)
			break
		}

		n := len(raddr)

		if _, er := io.ReadFull(rc, b[n:n+4]); er != nil {
			if ne := net.Error(nil); errors.As(err, &ne) {
				if ne.Timeout() {
					break
				}
			}
			if errors.Is(er, smux.ErrTimeout) || errors.Is(er, io.ErrClosedPipe) {
				break
			}
			err = fmt.Errorf("read size info error: %w", er)
			break
		}

		n += (int(b[n])<<8 | int(b[n+1]))

		if _, er := io.ReadFull(rc, b[len(raddr):n]); er != nil {
			if ne := net.Error(nil); errors.As(err, &ne) {
				if ne.Timeout() {
					break
				}
			}
			if errors.Is(er, smux.ErrTimeout) || errors.Is(er, io.ErrClosedPipe) {
				break
			}
			err = fmt.Errorf("read packet error: %w", er)
			break
		}

		if _, ew := conn.WriteFrom(b[len(raddr):n], raddr); ew != nil {
			err = fmt.Errorf("write packet error: %w", ew)
			break
		}
	}

	conn.Close()
	rc.Close()

	if err != nil {
		<-errCh
	} else {
		err = <-errCh
	}

	if errors.Is(err, os.ErrDeadlineExceeded) {
		err = nil
	}

	return err
}

func copyWithChannel(conn netstack.PacketConn, rc net.Conn, timeout time.Duration, errCh chan error) {
	slice := netstack.Get()
	defer netstack.Put(slice)
	b := slice.Get()

	b[socks.MaxAddrLen+2], b[socks.MaxAddrLen+3] = 0x0d, 0x0a

	buf := [socks.MaxAddrLen]byte{}
	for {
		n, tgt, err := conn.ReadTo(b[socks.MaxAddrLen+4:])
		if err != nil {
			if err == io.EOF {
				errCh <- nil
				break
			}
			errCh <- err
			break
		}
		b[socks.MaxAddrLen], b[socks.MaxAddrLen+1] = byte(n>>8), byte(n)

		addr, ok := tgt.(socks.Addr)
		if !ok {
			addr, err = socks.ResolveAddrBuffer(tgt, buf[:])
			if err != nil {
				errCh <- fmt.Errorf("resolve addr error: %w", err)
				break
			}
		}

		copy(b[socks.MaxAddrLen-len(addr):], addr)

		rc.SetWriteDeadline(time.Now().Add(timeout))
		_, err = rc.Write(b[socks.MaxAddrLen-len(addr) : socks.MaxAddrLen+4+n])
		if err != nil {
			errCh <- err
			break
		}
	}
}

type emptyReader struct{}

func (*emptyReader) Read(b []byte) (int, error) {
	return 0, io.EOF
}

type wsConn struct {
	*websocket.Conn
	Reader io.Reader
}

func (conn *wsConn) Read(b []byte) (int, error) {
	n, err := conn.Reader.Read(b)
	if n > 0 {
		return n, nil
	}

	_, conn.Reader, err = conn.Conn.NextReader()
	if err != nil {
		if we := (*websocket.CloseError)(nil); errors.As(err, &we) {
			return 0, io.EOF
		}
		return 0, err
	}

	n, err = conn.Reader.Read(b)
	return n, nil
}

func (conn *wsConn) Write(b []byte) (int, error) {
	err := conn.Conn.WriteMessage(websocket.BinaryMessage, b)
	if err != nil {
		if we := (*websocket.CloseError)(nil); errors.As(err, &we) {
			return 0, io.EOF
		}
		return 0, err
	}
	return len(b), nil
}

func (conn *wsConn) SetDeadline(t time.Time) error {
	conn.SetReadDeadline(t)
	conn.SetWriteDeadline(t)
	return nil
}

func (conn *wsConn) Close() (err error) {
	err = conn.Conn.WriteControl(websocket.CloseMessage, websocket.FormatCloseMessage(websocket.CloseNormalClosure, ""), time.Now().Add(time.Second*5))
	conn.Conn.Close()
	return
}
