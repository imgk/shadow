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

	"github.com/imgk/shadow/common"
	"github.com/imgk/shadow/protocol"
	"github.com/imgk/shadow/protocol/shadowsocks/core"
)

func init() {
	protocol.RegisterHandler("trojan", func(s string, timeout time.Duration) (common.Handler, error) {
		return NewHandler(s, timeout)
	})
}

const (
	HeaderLen = 56
)

const (
	cmdConnect   = 1
	cmdAssocaite = 3
)

type Dialer struct {
	dialer net.Dialer
	addr   string
}

func (d *Dialer) Dial(network, addr string) (net.Conn, error) {
	conn, err := d.dialer.Dial(network, d.addr)
	if nc, ok := conn.(*net.TCPConn); ok {
		nc.SetKeepAlive(true)
	}
	return conn, err
}

func (d *Dialer) DialContext(ctx context.Context, network, addr string) (net.Conn, error) {
	conn, err := d.dialer.DialContext(ctx, network, d.addr)
	if nc, ok := conn.(*net.TCPConn); ok {
		nc.SetKeepAlive(true)
	}
	return conn, err
}

type Connector interface {
	Connect() (net.Conn, error)
}

type TLS struct {
	server string
	dialer Dialer
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
	conn = &WebSocketConn{Conn: wc, Reader: emptyReader{}}
	return
}

type MuxConfig struct {
	sync.Mutex
	config smux.Config
	max    int
	conns  map[*smux.Session]struct{}
}

type Handler struct {
	connector  Connector
	cipher     core.Cipher
	mux        MuxConfig
	muxEnabled bool

	header  [HeaderLen + 2 + 8 + 2]byte
	timeout time.Duration
	server  string
	ticker  *time.Ticker
}

func NewHandler(url string, timeout time.Duration) (*Handler, error) {
	opt, err := ParseUrl(url)
	if err != nil {
		return nil, err
	}

	addr, err := net.ResolveUDPAddr("udp", opt.Server)
	if err != nil {
		return nil, err
	}

	host := addr.String()
	hd := &Handler{
		timeout: timeout,
		server:  host,
	}
	tlsConfig := &tls.Config{
		ServerName:         opt.DomainName,
		ClientSessionCache: tls.NewLRUClientSessionCache(32),
		InsecureSkipVerify: false,
	}
	dialer := Dialer{
		dialer: net.Dialer{},
		addr:   host,
	}

	hash := sha256.Sum224([]byte(opt.Password))
	hex.Encode(hd.header[:HeaderLen], hash[:])
	hd.header[HeaderLen], hd.header[HeaderLen+1] = 0x0d, 0x0a

	switch opt.Transport {
	case "websocket":
		hd.connector = &WebSocket{
			dialer: websocket.Dialer{
				NetDial:         dialer.Dial,
				NetDialContext:  dialer.DialContext,
				TLSClientConfig: tlsConfig,
			},
			addr: "wss://" + opt.DomainName + opt.Path,
		}
	case "tls":
		hd.connector = &TLS{
			server: hd.server,
			dialer: dialer,
			config: tlsConfig,
		}
	}

	cipher, err := core.NewCipher(opt.Aead, opt.AeadPassword)
	if err != nil {
		return nil, err
	}
	hd.cipher = cipher

	switch opt.Mux {
	case "off":
		hd.muxEnabled = false
	case "v1":
		hd.mux = MuxConfig{
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

		copy(hd.header[HeaderLen+2:], []byte{0x7f, common.AddrTypeIPv4, 0, 0, 0, 0, 0, 0, 0x0d, 0x0a})

		hd.muxEnabled = true
		hd.ticker = time.NewTicker(time.Minute * 3)
		go hd.closeIdleSession()
	case "v2":
		hd.mux = MuxConfig{
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

		copy(hd.header[HeaderLen+2:], []byte{0x8f, common.AddrTypeIPv4, 0, 0, 0, 0, 0, 0, 0x0d, 0x0a})

		hd.muxEnabled = true
		hd.ticker = time.NewTicker(time.Minute * 3)
		go hd.closeIdleSession()
	}

	return hd, nil
}

func (h *Handler) Close() error {
	if h.ticker != nil {
		h.ticker.Stop()
	}
	return nil
}

func (h *Handler) closeIdleSession() {
	for range h.ticker.C {
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

func (h *Handler) Connect() (conn net.Conn, err error) {
	conn, err = h.connector.Connect()
	conn = core.NewConn(conn, h.cipher)
	return
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
							if sess.NumStreams() == 0 {
								sess.Close()
								t.Stop()
								return
							}
						}
					}(sess)
					delete(h.mux.conns, sess)
					continue
				}
				continue
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
	target := [HeaderLen + 2 + 1 + common.MaxAddrLen + 2]byte{}

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

	addr, ok := tgt.(common.Addr)
	if ok {
		copy(target[HeaderLen+2+1:], addr)
		n = HeaderLen + 2 + 1 + len(addr) + 2
	} else {
		addr, er := common.ResolveAddrBuffer(tgt, target[HeaderLen+2+1:])
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
	target := [HeaderLen + 2 + 1 + common.MaxAddrLen + 2]byte{}

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

	addr, ok := tgt.(common.Addr)
	if ok {
		n += copy(target[1:], addr)
	} else {
		addr, er := common.ResolveAddrBuffer(tgt, target[1:])
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
	defer conn.Close()

	rc, err := h.Dial(conn.LocalAddr(), cmdAssocaite)
	if err != nil {
		return err
	}
	defer rc.Close()

	errCh := make(chan error, 1)
	go copyWithChannel(conn, rc, h.timeout, errCh)

	b := common.Get()
	defer common.Put(b)

	for {
		rc.SetReadDeadline(time.Now().Add(h.timeout))
		raddr, er := common.ReadAddrBuffer(rc, b)
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

func copyWithChannel(conn common.PacketConn, rc net.Conn, timeout time.Duration, errCh chan error) {
	b := common.Get()
	defer common.Put(b)

	b[common.MaxAddrLen+2], b[common.MaxAddrLen+3] = 0x0d, 0x0a

	buf := [common.MaxAddrLen]byte{}
	for {
		n, tgt, err := conn.ReadTo(b[common.MaxAddrLen+4:])
		if err != nil {
			if err == io.EOF {
				errCh <- nil
				break
			}
			errCh <- err
			break
		}
		b[common.MaxAddrLen], b[common.MaxAddrLen+1] = byte(n>>8), byte(n)

		addr, ok := tgt.(common.Addr)
		if !ok {
			addr, err = common.ResolveAddrBuffer(tgt, buf[:])
			if err != nil {
				errCh <- fmt.Errorf("resolve addr error: %w", err)
				break
			}
		}

		copy(b[common.MaxAddrLen-len(addr):], addr)

		rc.SetWriteDeadline(time.Now().Add(timeout))
		_, err = rc.Write(b[common.MaxAddrLen-len(addr) : common.MaxAddrLen+4+n])
		if err != nil {
			errCh <- err
			break
		}
	}
}

type emptyReader struct{}

func (emptyReader) Read(b []byte) (int, error) {
	return 0, io.EOF
}

type WebSocketConn struct {
	*websocket.Conn
	Reader io.Reader
}

func (conn *WebSocketConn) Read(b []byte) (int, error) {
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

func (conn *WebSocketConn) Write(b []byte) (int, error) {
	err := conn.Conn.WriteMessage(websocket.BinaryMessage, b)
	if err != nil {
		if we := (*websocket.CloseError)(nil); errors.As(err, &we) {
			return 0, io.EOF
		}
		return 0, err
	}
	return len(b), nil
}

func (conn *WebSocketConn) SetDeadline(t time.Time) error {
	conn.SetReadDeadline(t)
	conn.SetWriteDeadline(t)
	return nil
}

func (conn *WebSocketConn) Close() (err error) {
	err = conn.Conn.WriteControl(websocket.CloseMessage, websocket.FormatCloseMessage(websocket.CloseNormalClosure, ""), time.Now().Add(time.Second*5))
	conn.Conn.Close()
	return
}
