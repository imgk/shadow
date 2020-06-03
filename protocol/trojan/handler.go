package trojan

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"fmt"
	"io"
	mrand "math/rand"
	"net"
	"sync"
	"time"

	"golang.org/x/crypto/pbkdf2"
	"golang.org/x/net/websocket"

	tls "github.com/refraction-networking/utls"
	"github.com/xtaci/smux"

	"github.com/imgk/shadow/netstack"
	"github.com/imgk/shadow/utils"
)

const (
	HexLen           = 56
	MaxUDPPacketSize = 4096 // Max 65536
)

const (
	Connect   = 1
	Assocaite = 3
)

type Stream struct {
	net.Conn
	io.Reader
	io.Writer
}

func NewCTRStream(conn net.Conn, block cipher.Block) (connection Stream, err error) {
	iv := make([]byte, aes.BlockSize)

	_, err = rand.Read(iv)
	if err != nil {
		return
	}

	_, err = conn.Write(iv)
	if err != nil {
		return
	}

	connection = Stream{
		Conn: conn,
		Reader: cipher.StreamReader{
			S: cipher.NewCTR(block, iv),
			R: conn,
		},
		Writer: cipher.StreamWriter{
			S: cipher.NewCTR(block, iv),
			W: conn,
		},
	}

	return
}

func (conn Stream) Read(b []byte) (int, error) {
	return conn.Reader.Read(b)
}

func (conn Stream) Write(b []byte) (int, error) {
	return conn.Writer.Write(b)
}

func (conn Stream) ReadFrom(r io.Reader) (int64, error) {
	return Copy(conn.Writer, r)
}

func (conn Stream) WriteTo(w io.Writer) (int64, error) {
	return Copy(w, conn.Reader)
}

type Mux struct {
	sync.Mutex
	*smux.Config
	Max int
	Map map[uint32]*smux.Session
}

type WebSocket struct {
	cipher.Block
	*websocket.Config
}

type Handler struct {
	*Mux
	*WebSocket
	*tls.Config
	header  [HexLen + 2 + 8 + 2]byte
	timeout time.Duration
	server  string
}

func NewHandler(url string, timeout time.Duration) (*Handler, error) {
	server, password, mux, path, err := ParseUrl(url)
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
			Map:    make(map[uint32]*smux.Session),
		}
		hd.Mux.Config.KeepAliveDisabled = false

		copy(hd.header[HexLen+2:], []byte{0x7f, utils.AddrTypeIPv4, 0, 0, 0, 0, 0, 0, 0x0d, 0x0a})

		go hd.CloseIdleSession()
	}

	if path != "" {
		block, err := aes.NewCipher(pbkdf2.Key([]byte(password), []byte{48, 149, 6, 18, 13, 193, 247, 116, 197, 135, 236, 175, 190, 209, 146, 48}, 32, aes.BlockSize, sha256.New))
		if err != nil {
			return nil, err
		}

		config, err := websocket.NewConfig("wss://"+host+path, "https://"+host)
		if err != nil {
			return nil, err
		}

		hd.WebSocket = &WebSocket{
			Block:  block,
			Config: config,
		}
	}

	return hd, nil
}

func (h *Handler) Connect() (conn net.Conn, err error) {
	conn, err = net.Dial("tcp", h.server)
	if err != nil {
		return
	}
	conn.(*net.TCPConn).SetKeepAlive(true)
	conn = tls.UClient(conn, h.Config, tls.HelloRandomized)

	if h.WebSocket == nil {
		return
	}

	CloseError := func(conn net.Conn) {
		if err != nil {
			conn.Close()
		}
	}
	defer CloseError(conn)

	conn, err = websocket.NewClient(h.WebSocket.Config, conn)
	if err != nil {
		err = fmt.Errorf("new websocket client error: %w", err)
		return
	}

	conn, err = NewCTRStream(conn, h.WebSocket.Block)
	if err != nil {
		err = fmt.Errorf("new obfs conn error: %w", err)
		return
	}

	return
}

func (h *Handler) ConnectMux() (conn net.Conn, err error) {
	h.Mux.Lock()
	defer h.Mux.Unlock()

	for k, item := range h.Mux.Map {
		if item.NumStreams() < h.Mux.Max {
			if item.IsClosed() {
				delete(h.Mux.Map, k)
				continue
			}

			conn, err = item.OpenStream()
			if err != nil {
				if err == smux.ErrGoAway {
					err = nil
					item.Close()
					delete(h.Mux.Map, k)
					continue
				}
			}

			return conn, err
		}
	}

	conn, err = h.Connect()
	if err != nil {
		return
	}

	CloseError := func(conn net.Conn) {
		if err != nil {
			conn.Close()
		}
	}
	defer CloseError(conn)

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

	h.Mux.Map[mrand.Uint32()] = sess

	return
}

func (h *Handler) CloseIdleSession() {
	t := time.NewTicker(time.Minute * 3)

	for {
		<-t.C

		h.Mux.Lock()
		for k, item := range h.Mux.Map {
			if item.IsClosed() {
				delete(h.Mux.Map, k)
				continue
			}

			if item.NumStreams() == 0 {
				item.Close()
				delete(h.Mux.Map, k)
			}
		}
		h.Mux.Unlock()
	}
}

func (h *Handler) Dial(tgt net.Addr, cmd byte) (conn net.Conn, err error) {
	target := make([]byte, HexLen+2+1+utils.MaxAddrLen+2)

	CloseError := func(conn net.Conn) {
		if err != nil {
			conn.Close()
		}
	}

	n := 0
	if h.Mux == nil {
		conn, err = h.Connect()
		if err != nil {
			return
		}
		defer CloseError(conn)

		n = copy(target[0:], h.header[:HexLen+2])
		target[HexLen+2] = cmd

		addr, ok := tgt.(utils.Addr)
		if !ok {
			addr, er := utils.ResolveAddrBuffer(tgt, target[HexLen+2+1:])
			if er != nil {
				err = fmt.Errorf("resolve addr error: %w", er)
				return
			}
			n = HexLen + 2 + 1 + len(addr) + 2
		} else {
			copy(target[HexLen+2+1:], addr)
			n = HexLen + 2 + 1 + len(addr) + 2
		}
		target[n-2], target[n-1] = 0x0d, 0x0a
	} else {
		conn, err = h.ConnectMux()
		if err != nil {
			return
		}
		defer CloseError(conn)

		target[0] = cmd

		addr, ok := tgt.(utils.Addr)
		if !ok {
			addr, er := utils.ResolveAddrBuffer(tgt, target[1:])
			if er != nil {
				err = fmt.Errorf("resolve addr error: %w", er)
				return
			}
			n = 1 + len(addr)
		} else {
			n = 1 + copy(target[1:], addr)
		}
	}

	if _, er := conn.Write(target[:n]); er != nil {
		err = fmt.Errorf("write to server %v error: %w", h.server, er)
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

	l, ok := conn.(DuplexConn)
	if !ok {
		l = NewDuplexConn(conn)
	}

	r, ok := rc.(DuplexConn)
	if !ok {
		r = NewDuplexConn(rc)
	}

	if err := relay(l, r); err != nil {
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

type DuplexConn interface {
	net.Conn
	CloseRead() error
	CloseWrite() error
}

type duplexConn struct {
	net.Conn
}

func NewDuplexConn(conn net.Conn) duplexConn {
	return duplexConn{Conn: conn}
}

func (conn duplexConn) CloseRead() error {
	return conn.SetReadDeadline(time.Now())
}

func (conn duplexConn) CloseWrite() error {
	return conn.SetWriteDeadline(time.Now())
}

func Copy(w io.Writer, r io.Reader) (n int64, err error) {
	if wt, ok := r.(io.WriterTo); ok {
		return wt.WriteTo(w)
	}
	if c, ok := r.(duplexConn); ok {
		if wt, ok := c.Conn.(io.WriterTo); ok {
			return wt.WriteTo(w)
		}
	}
	if rt, ok := w.(io.ReaderFrom); ok {
		return rt.ReadFrom(r)
	}
	if c, ok := w.(duplexConn); ok {
		if rt, ok := c.Conn.(io.ReaderFrom); ok {
			return rt.ReadFrom(r)
		}
	}

	b := make([]byte, 4096)
	for {
		nr, er := r.Read(b)
		if nr > 0 {
			nw, ew := w.Write(b[:nr])
			if nw > 0 {
				n += int64(nw)
			}
			if ew != nil {
				err = ew
				break
			}
			if nr != nw {
				err = io.ErrShortWrite
				break
			}
		}
		if er != nil {
			if er != io.EOF {
				err = er
			}
			break
		}
	}

	return n, err
}

func relay(c, rc DuplexConn) error {
	errCh := make(chan error, 1)
	go copyWaitError(c, rc, errCh)

	_, err := Copy(rc, c)
	if err != nil {
		rc.Close()
		c.Close()
	} else {
		rc.CloseWrite()
		c.CloseRead()
	}

	if err != nil {
		<-errCh
		return err
	}

	return <-errCh
}

func copyWaitError(c, rc DuplexConn, errCh chan error) {
	_, err := Copy(c, rc)
	if err != nil {
		c.Close()
		rc.Close()
	} else {
		c.CloseWrite()
		rc.CloseRead()
	}

	errCh <- err
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

	b := make([]byte, MaxUDPPacketSize)
	for {
		rc.SetDeadline(time.Now().Add(h.timeout))
		raddr, er := utils.ReadAddrBuffer(rc, b)
		if er != nil {
			if ne, ok := er.(net.Error); ok {
				if ne.Timeout() {
					break
				}
			}

			if er == smux.ErrTimeout || er == io.ErrClosedPipe {
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

			if er == smux.ErrTimeout || er == io.ErrClosedPipe {
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
	b := make([]byte, MaxUDPPacketSize)
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

		rc.SetDeadline(time.Now().Add(timeout))
		_, err = rc.Write(b[utils.MaxAddrLen-len(addr) : utils.MaxAddrLen+4+n])
		if err != nil {
			errCh <- err
			break
		}
	}

	return
}
