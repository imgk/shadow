package trojan

import (
	"bytes"
	"context"
	"crypto/tls"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"fmt"
	"io"
	"net"
	"sync"
	"time"

	"github.com/gorilla/websocket"
	"github.com/xtaci/smux"

	"github.com/imgk/shadow/netstack"
	"github.com/imgk/shadow/protocol/shadowsocks"
	"github.com/imgk/shadow/utils"
)

const (
	HexLen        = 56
	MaxBufferSize = 4096 // Max 65536
)

const (
	Connect   = 1
	Assocaite = 3
)

var DefaultDialer = Dialer{
	Dialer: net.Dialer{},
}

type Dialer struct {
	net.Dialer
}

func (d Dialer) Dial(network, addr string) (net.Conn, error) {
	conn, err := d.Dialer.Dial(network, addr)
	if nc, ok := conn.(*net.TCPConn); ok {
		nc.SetKeepAlive(true)
	}
	return conn, err
}

func (d Dialer) DialContext(ctx context.Context, network, addr string) (net.Conn, error) {
	conn, err := d.Dialer.DialContext(ctx, network, addr)
	if nc, ok := conn.(*net.TCPConn); ok {
		nc.SetKeepAlive(true)
	}
	return conn, err
}

type Mux struct {
	sync.Mutex
	*smux.Config
	Max int
	Map map[*smux.Session]struct{}
}

type WebSocket struct {
	websocket.Dialer
	Addr   string
	Cipher shadowsocks.Cipher
}

type Handler struct {
	Mux       *Mux
	WebSocket *WebSocket
	Config    *tls.Config
	header    [HexLen + 2 + 8 + 2]byte
	timeout   time.Duration
	server    string
}

func NewHandler(url string, timeout time.Duration) (*Handler, error) {
	server, cipher, password, mux, path, err := ParseUrl(url)
	if err != nil {
		return nil, err
	}

	addr, err := net.ResolveUDPAddr("udp", server)
	if err != nil {
		return nil, err
	}

	host, _, err := net.SplitHostPort(server)
	if err != nil {
		return nil, err
	}

	hd := &Handler{
		Config: &tls.Config{
			ServerName:         host,
			ClientSessionCache: tls.NewLRUClientSessionCache(32),
			InsecureSkipVerify: false,
		},
		timeout: timeout,
		server:  addr.String(),
	}

	hash := sha256.Sum224([]byte(password))
	hex.Encode(hd.header[:HexLen], hash[:])
	hd.header[HexLen], hd.header[HexLen+1] = 0x0d, 0x0a

	if mux != "" {
		hd.Mux = &Mux{
			Mutex:  sync.Mutex{},
			Config: smux.DefaultConfig(),
			Max:    8,
			Map:    make(map[*smux.Session]struct{}),
		}

		copy(hd.header[HexLen+2:], []byte{0x7f, utils.AddrTypeIPv4, 0, 0, 0, 0, 0, 0, 0x0d, 0x0a})

		go hd.CloseIdleSession()
	}

	if path != "" {
		ciph, err := shadowsocks.NewCipher(cipher, password)
		if err != nil {
			return nil, err
		}

		hd.WebSocket = &WebSocket{
			Dialer: websocket.Dialer{
				NetDial:         DefaultDialer.Dial,
				NetDialContext:  DefaultDialer.DialContext,
				TLSClientConfig: hd.Config,
			},
			Addr:   "wss://"+host+path,
			Cipher: ciph,
		}
	}

	return hd, nil
}

func (h *Handler) Connect() (conn net.Conn, err error) {
	if h.WebSocket != nil {
		ws, _, er := h.WebSocket.Dialer.Dial(h.WebSocket.Addr, nil)
		if er != nil {
			err = er
			return
		}

		conn = shadowsocks.NewConn(&WebConn{Conn: ws, Reader: bytes.NewReader(nil)}, h.WebSocket.Cipher)
		return
	}

	conn, err = DefaultDialer.Dial("tcp", h.server)
	if err != nil {
		return
	}

	conn = tls.Client(conn, h.Config.Clone())
	if err = conn.(*tls.Conn).Handshake(); err != nil {
		conn.Close()
		return
	}

	return
}

func (h *Handler) ConnectMux() (conn net.Conn, err error) {
	h.Mux.Lock()
	for sess, _ := range h.Mux.Map {
		if sess.NumStreams() < h.Mux.Max {
			if sess.IsClosed() {
				delete(h.Mux.Map, sess)
				continue
			}

			conn, err = sess.OpenStream()
			if err != nil {
				if errors.Is(err, smux.ErrGoAway) {
					go CloseLater(sess)
					delete(h.Mux.Map, sess)
					continue
				}
				continue
			}

			h.Mux.Unlock()
			return
		}
	}
	h.Mux.Unlock()

	conn, err = h.ConnectMuxNew()
	return
}

func CloseLater(sess *smux.Session) {
	t := time.NewTicker(time.Minute)

	for {
		<- t.C

		if sess.NumStreams() == 0 {
			sess.Close()
			return
		}
	}
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

	sess, err := smux.Client(conn, h.Mux.Config)
	if err != nil {
		return
	}

	conn, err = sess.OpenStream()
	if err != nil {
		sess.Close()
		return
	}

	h.Mux.Lock()
	h.Mux.Map[sess] = struct{}{}
	h.Mux.Unlock()

	return
}

func (h *Handler) CloseIdleSession() {
	t := time.NewTicker(time.Minute * 3)

	for {
		<-t.C

		h.Mux.Lock()
		for sess, _ := range h.Mux.Map {
			if sess.IsClosed() {
				delete(h.Mux.Map, sess)
				continue
			}

			if sess.NumStreams() == 0 {
				sess.Close()
				delete(h.Mux.Map, sess)
			}
		}
		h.Mux.Unlock()
	}
}

func (h *Handler) Dial(tgt net.Addr, cmd byte) (conn net.Conn, err error) {
	if h.Mux != nil {
		return h.DialMux(tgt, cmd)
	}

	target := make([]byte, HexLen+2+1+utils.MaxAddrLen+2)
	conn, err = h.Connect()
	if err != nil {
		return
	}
	defer func() {
		if err != nil {
			conn.Close()
		}
	}()

	n := copy(target[0:], h.header[:HexLen+2])
	target[HexLen+2] = cmd

	addr, ok := tgt.(utils.Addr)
	if ok {
		copy(target[HexLen+2+1:], addr)
		n = HexLen + 2 + 1 + len(addr) + 2
	} else {
		addr, er := utils.ResolveAddrBuffer(tgt, target[HexLen+2+1:])
		if er != nil {
			err = fmt.Errorf("resolve addr error: %w", er)
			return
		}
		n = HexLen + 2 + 1 + len(addr) + 2
	}
	target[n-2], target[n-1] = 0x0d, 0x0a

	if _, er := conn.Write(target[:n]); er != nil {
		err = fmt.Errorf("write to server %v error: %w", h.server, er)
		return
	}

	return
}

func (h *Handler) DialMux(tgt net.Addr, cmd byte) (conn net.Conn, err error) {
	target := make([]byte, HexLen+2+1+utils.MaxAddrLen+2)
	conn, err = h.ConnectMux()
	if err != nil {
		return
	}
	defer func() {
		if err != nil {
			conn.Close()
		}
	}()

	n := 0
	target[0] = cmd

	addr, ok := tgt.(utils.Addr)
	if ok {
		n = 1 + copy(target[1:], addr)
	} else {
		addr, er := utils.ResolveAddrBuffer(tgt, target[1:])
		if er != nil {
			err = fmt.Errorf("resolve addr error: %w", er)
			return
		}
		n = 1 + len(addr)
	}

	if _, er := conn.Write(target[:n]); er != nil {
		conn.Close()

		conn, err = h.ConnectMuxNew()
		if err != nil {
			return
		}

		if _, er := conn.Write(target[:n]); er != nil {
			err = fmt.Errorf("write to server %v error: %w", h.server, er)
			return
		}

		return
	}

	return
}

func (h *Handler) Handle(conn net.Conn, tgt net.Addr) error {
	defer conn.Close()

	rc, err := h.Dial(tgt, Connect)
	if err != nil {
		return err
	}
	defer rc.Close()

	if err := netstack.Relay(conn, rc); err != nil {
		if ne, ok := err.(net.Error); ok {
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

	rc, err := h.Dial(conn.LocalAddr(), Assocaite)
	if err != nil {
		return err
	}
	defer rc.Close()

	errCh := make(chan error, 1)
	go copyWithChannel(conn, rc, h.timeout, errCh)

	b := make([]byte, MaxBufferSize)
	for {
		rc.SetReadDeadline(time.Now().Add(h.timeout))
		raddr, er := utils.ReadAddrBuffer(rc, b)
		if er != nil {
			if ne, ok := er.(net.Error); ok {
				if ne.Timeout() {
					break
				}
			}

			if errors.Is(er, smux.ErrTimeout) || errors.Is(er, io.ErrClosedPipe) {
				break
			}

			err = fmt.Errorf("read addr error: %w", er)
			break
		}

		n := len(raddr)

		if _, er := io.ReadFull(rc, b[n:n+4]); er != nil {
			if ne, ok := er.(net.Error); ok {
				if ne.Timeout() {
					break
				}
			}

			if er == smux.ErrTimeout || er == io.ErrClosedPipe {
				break
			}

			err = fmt.Errorf("read size info error: %w", er)
			break
		}

		n += (int(b[n])<<8 | int(b[n+1]))

		if _, er := io.ReadFull(rc, b[len(raddr):n]); er != nil {
			if ne, ok := er.(net.Error); ok {
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

		_, er = conn.WriteFrom(b[len(raddr):n], raddr)
		if er != nil {
			err = fmt.Errorf("write packet error: %w", er)
			break
		}
	}

	conn.Close()
	rc.Close()

	if err != nil {
		<-errCh
		return err
	}

	return <-errCh
}

func copyWithChannel(conn netstack.PacketConn, rc net.Conn, timeout time.Duration, errCh chan error) {
	b := make([]byte, MaxBufferSize)
	b[utils.MaxAddrLen+2], b[utils.MaxAddrLen+3] = 0x0d, 0x0a

	for {
		n, tgt, err := conn.ReadTo(b[utils.MaxAddrLen+4:])
		if err != nil {
			if err == io.EOF {
				errCh <- nil
				break
			}
			errCh <- err
			break
		}
		b[utils.MaxAddrLen], b[utils.MaxAddrLen+1] = byte(n>>8), byte(n)

		addr, ok := tgt.(utils.Addr)
		if !ok {
			addr, err = utils.ResolveAddrBuffer(tgt, make([]byte, utils.MaxAddrLen))
			if err != nil {
				errCh <- fmt.Errorf("resolve addr error: %v", err)
				break
			}
		}

		copy(b[utils.MaxAddrLen-len(addr):], addr)

		rc.SetWriteDeadline(time.Now().Add(timeout))
		_, err = rc.Write(b[utils.MaxAddrLen-len(addr):utils.MaxAddrLen+4+n])
		if err != nil {
			errCh <- err
			break
		}
	}

	return
}

type WebConn struct {
	*websocket.Conn
	Reader io.Reader
}

func (conn *WebConn) Read(b []byte) (int, error) {
	n, err := conn.Reader.Read(b)
	if n != 0 {
		return n, nil
	}

	_, conn.Reader, err = conn.Conn.NextReader()
	if err != nil {
		return 0, err
	}

	n, err = conn.Reader.Read(b)
	return n, nil
}

func (conn *WebConn) Write(b []byte) (int, error) {
	err := conn.Conn.WriteMessage(websocket.BinaryMessage, b)
	if err != nil {
		return 0, err
	}
	return len(b), nil
}

func (conn *WebConn) SetDeadline(t time.Time) error {
	conn.SetReadDeadline(t)
	conn.SetWriteDeadline(t)
	return nil
}

func (conn *WebConn) Close() (err error) {
	err = conn.Conn.WriteControl(websocket.CloseMessage, websocket.FormatCloseMessage(websocket.CloseNormalClosure, ""), time.Now().Add(time.Second*5))
	conn.Conn.Close()
	return
}
