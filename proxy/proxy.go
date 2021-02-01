package proxy

import (
	"bytes"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"os"
	"strconv"
	"time"

	"github.com/imgk/shadow/netstack"
	"github.com/imgk/shadow/pkg/gonet"
	"github.com/imgk/shadow/pkg/logger"
	"github.com/imgk/shadow/pkg/pool"
	"github.com/imgk/shadow/pkg/socks"
	"github.com/imgk/shadow/pkg/suffixtree"
	"github.com/imgk/shadow/pkg/xerror"
)

// fake net.Listener
type fakeListener struct {
	closed chan struct{}
	conns  chan net.Conn
	addr   net.Addr
}

func newFakeListener(addr net.Addr) *fakeListener {
	return &fakeListener{
		closed: make(chan struct{}),
		conns:  make(chan net.Conn, 5),
		addr:   addr,
	}
}

func (s *fakeListener) Accept() (net.Conn, error) {
	select {
	case <-s.closed:
	case conn := <-s.conns:
		return conn, nil
	}
	return nil, os.ErrClosed
}

func (s *fakeListener) Receive(conn net.Conn) {
	select {
	case <-s.closed:
	case s.conns <- conn:
	}
}

func (s *fakeListener) Close() error {
	select {
	case <-s.closed:
		return nil
	default:
		close(s.closed)
	}
	return nil
}

func (s *fakeListener) Addr() net.Addr {
	return s.addr
}

// fake net.Conn
type fakeConn struct {
	net.Conn
	reader io.Reader
}

func newFakeConn(conn net.Conn, reader io.Reader) *fakeConn {
	return &fakeConn{
		Conn:   conn,
		reader: reader,
	}
}

func (conn *fakeConn) CloseRead() error {
	if close, ok := conn.Conn.(gonet.CloseReader); ok {
		return close.CloseRead()
	}
	conn.Conn.SetReadDeadline(time.Now())
	return conn.Conn.Close()
}

func (conn *fakeConn) CloseWrite() error {
	if close, ok := conn.Conn.(gonet.CloseWriter); ok {
		return close.CloseWrite()
	}
	conn.Conn.SetWriteDeadline(time.Now())
	return conn.Conn.Close()
}

func (conn *fakeConn) Read(b []byte) (int, error) {
	return conn.reader.Read(b)
}

// fake gonet.PacketConn
type fakePacketConn struct {
	addr net.Addr
	net.PacketConn
}

func newPacketConn(src net.Addr, pc net.PacketConn) *fakePacketConn {
	return &fakePacketConn{
		addr:       src,
		PacketConn: pc,
	}
}

func (pc *fakePacketConn) RemoteAddr() net.Addr {
	return pc.addr
}

func (pc *fakePacketConn) ReadTo(b []byte) (n int, addr net.Addr, err error) {
	const MaxBufferSize = 16 << 10
	sc, buf := pool.Pool.Get(MaxBufferSize)
	defer pool.Pool.Put(sc)

	n, _, err = pc.PacketConn.ReadFrom(buf)
	if err != nil {
		return
	}
	tgt, err := socks.ParseAddr(buf[3:])
	if err != nil {
		return
	}
	addr = socks.Addr(append(make([]byte, 0, len(tgt)), tgt...))
	n = copy(b, buf[3+len(tgt):n])
	return
}

func (pc *fakePacketConn) WriteFrom(b []byte, addr net.Addr) (n int, err error) {
	const MaxBufferSize = 16 << 10
	sc, buf := pool.Pool.Get(MaxBufferSize)
	defer pool.Pool.Put(sc)

	src, err := socks.ResolveAddrBuffer(addr, b[3:])
	if err != nil {
		return
	}
	n = copy(buf[3+len(src):], b)
	_, err = pc.PacketConn.WriteTo(buf[:3+len(src)+n], pc.addr)
	return
}

// a combined socks5/http proxy server
type proxyServer struct {
	Logger logger.Logger
	router *http.ServeMux

	// Convert fake IP and handle connections
	tree    *suffixtree.DomainTree
	handler gonet.Handler

	// Listen
	http.Server
	netLisener net.Listener
	listener   *fakeListener

	closed chan struct{}
}

func NewProxyServer(ln net.Listener, logger logger.Logger, handler gonet.Handler, tree *suffixtree.DomainTree, router *http.ServeMux) *proxyServer {
	s := &proxyServer{
		Logger:     logger,
		router:     router,
		tree:       tree,
		handler:    handler,
		netLisener: ln,
		listener:   newFakeListener(ln.Addr()),
		closed:     make(chan struct{}),
	}
	s.Server.Handler = http.Handler(s)
	return s
}

// accept net.Conn
func (s *proxyServer) Serve() {
	go s.Server.Serve(s.listener)

	for {
		conn, err := s.netLisener.Accept()
		if err != nil {
			return
		}
		go func(c net.Conn) {
			pc, b, ok, err := s.handshake(c)
			if err != nil {
				if errors.Is(err, io.EOF) {
					return
				}
				s.Logger.Error("handshake error: %v", err)
				return
			}
			if ok {
				s.proxySocks(c, pc, b)
				return
			}
			s.listener.Receive(newFakeConn(c, io.MultiReader(bytes.NewReader(b), c)))
		}(conn)
	}
}

// serve as a http server and http proxy server
// support GET and CONNECT method
func (s *proxyServer) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	if handler, pattern := s.router.Handler(r); pattern != "" {
		handler.ServeHTTP(w, r)
		return
	}

	switch r.Method {
	case http.MethodGet:
		if r.URL.Host == "" {
			http.HandlerFunc(http.NotFound).ServeHTTP(w, r)
			return
		}
		s.proxyGet(w, r)
	case http.MethodConnect:
		s.proxyConnect(w, r)
	default:
		http.HandlerFunc(http.NotFound).ServeHTTP(w, r)
	}
}

func (s *proxyServer) Close() (err error) {
	select {
	case <-s.closed:
		return
	default:
		close(s.closed)
	}

	err = xerror.CombineError(s.netLisener.Close(), s.listener.Close(), s.Server.Close())
	return
}

func (s *proxyServer) lookupIP(ip net.IP, b []byte) (socks.Addr, error) {
	if opt := s.tree.Load(fmt.Sprintf("%d.%d.18.198.in-addr.arpa.", ip[3], ip[2])); opt != nil {
		de := opt.(*netstack.DomainEntry)

		b[0] = socks.AddrTypeDomain
		b[1] = byte(len(de.PTR.Ptr))
		n := copy(b[2:], de.PTR.Ptr[:])
		return b[:2+n+2], nil
	}
	return nil, netstack.ErrNotFound
}

// handshake
func (s *proxyServer) handshake(conn net.Conn) (pc net.PacketConn, tgt []byte, ok bool, err error) {
	b := [3 + socks.MaxAddrLen]byte{}
	// read socks5 header
	if _, err = io.ReadFull(conn, b[:2]); err != nil {
		return
	}
	if b[0] != 0x05 {
		ok = false
		tgt = append(make([]byte, 0, 2), b[:2]...)
		return
	}
	ok = true
	// verify authentication
	if _, err = io.ReadFull(conn, b[2:2+b[1]]); err != nil {
		return
	}
	err = errors.New("no authentication supported")
	for _, v := range b[2 : 2+b[1]] {
		if v == 0 {
			err = nil
			break
		}
	}
	if err != nil {
		return
	}

	// write back auth method
	if _, err = conn.Write([]byte{0x05, 0x00}); err != nil {
		return
	}

	// read address
	if _, err = io.ReadFull(conn, b[:3]); err != nil {
		return
	}
	switch b[1] {
	case 0x01:
	case 0x03:
		pc, err = net.ListenPacket("udp", ":")
		if err != nil {
			return
		}
		defer func(conn net.PacketConn) {
			if err != nil {
				conn.Close()
			}
		}(pc)
	default:
		err = errors.New(fmt.Sprintf("socks cmd error: %v", b[1]))
		return
	}

	bb := make([]byte, socks.MaxAddrLen)
	tgt, err = socks.ReadAddrBuffer(conn, bb)
	if err != nil {
		return
	}
	if bb[0] == socks.AddrTypeIPv4 {
		if bb[1] == 198 && bb[2] == 18 {
			p1 := bb[1+net.IPv4len]
			p2 := bb[1+net.IPv4len+1]
			tgt, err = s.lookupIP(net.IP(bb[1:1+net.IPv4len]), bb)
			if err != nil {
				return
			}
			tgt[len(tgt)-2] = p1
			tgt[len(tgt)-1] = p2
		}
	}

	// write back address
	addr := socks.Addr{}
	switch b[1] {
	case 0x01:
		addr, err = socks.ResolveAddrBuffer(conn.LocalAddr(), b[3:])
	case 0x03:
		addr, err = socks.ResolveAddrBuffer(pc.LocalAddr(), b[3:])
	}
	if err != nil {
		return
	}
	b[1] = 0x00
	_, err = conn.Write(b[:3+len(addr)])
	return
}

// handle socks5 proxy
func (s *proxyServer) proxySocks(conn net.Conn, pc net.PacketConn, addr socks.Addr) {
	defer conn.Close()

	if pc != nil {
		defer pc.Close()

		src, err := socks.ResolveUDPAddr(addr)
		if err != nil {
			s.Logger.Error("resolve udp addr error: %v", err)
			return
		}

		go func(conn net.Conn, pc net.PacketConn) {
			b := make([]byte, 1)
			for {
				_, err := conn.Read(b)
				if ne := net.Error(nil); errors.As(err, &ne) {
					if ne.Timeout() {
						continue
					}
				}
				pc.SetReadDeadline(time.Now())
			}
		}(conn, pc)

		s.Logger.Info("proxyd %v <-UDP-> all", addr)
		if err := s.handler.HandlePacket(newPacketConn(src, pc)); err != nil {
			if errors.Is(err, os.ErrDeadlineExceeded) {
				return
			}
			s.Logger.Error("handle udp error: %v", err)
		}
		return
	}

	s.Logger.Info("proxyd %v <-TCP-> %v", conn.RemoteAddr(), addr)
	if err := s.handler.Handle(conn, addr); err != nil {
		s.Logger.Error("handle tcp error: %v", err)
	}
}

var errEmptyAddress = errors.New("nil address error")

// handle http proxy GET
func (s *proxyServer) proxyGet(w http.ResponseWriter, r *http.Request) {
	b := [socks.MaxAddrLen]byte{}
	addr, err := s.parseAddr(r.Host, "80", b[:])
	if err != nil {
		if errors.Is(err, errEmptyAddress) {
			return
		}
		s.Logger.Error("parse url host error: %v", err)
		return
	}

	src, dst := net.Pipe()
	t := http.Transport{
		Dial: func(network, addr string) (net.Conn, error) {
			return src, nil
		},
	}
	defer dst.Close()

	s.Logger.Info("proxyd %v <-TCP-> %v", r.RemoteAddr, addr)
	go func(conn net.Conn, addr net.Addr) {
		if err := s.handler.Handle(conn, addr); err != nil {
			s.Logger.Error("handle http conn error: %v", err)
		}
	}(dst, addr)

	resp, err := t.RoundTrip(r)
	if err != nil {
		return
	}
	defer resp.Body.Close()

	for k, values := range resp.Header {
		for _, v := range values {
			w.Header().Add(k, v)
		}
	}
	w.WriteHeader(resp.StatusCode)

	if _, err := gonet.Copy(w, resp.Body); err != nil {
		if errors.Is(err, io.EOF) {
			return
		}
		s.Logger.Error("copy response body error: %v", err)
	}
}

// handle http proxy CONNECT
func (s *proxyServer) proxyConnect(w http.ResponseWriter, r *http.Request) {
	host, port, err := net.SplitHostPort(r.Host)
	if err != nil {
		return
	}

	b := [socks.MaxAddrLen]byte{}
	addr, err := s.parseAddr(host, port, b[:])
	if err != nil {
		s.Logger.Error("parse url host error: %v", err)
		return
	}

	rw, ok := w.(http.Hijacker)
	if !ok {
		s.Logger.Error("not a http.Hijacker")
		return
	}
	conn, _, err := rw.Hijack()
	if err != nil {
		s.Logger.Error("http hijack error: %v", err)
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}
	conn.Write([]byte("HTTP/1.1 200 Connection Established\r\n\r\n"))

	s.Logger.Info("proxyd %v <-TCP-> %v", conn.RemoteAddr(), addr)
	if err := s.handler.Handle(conn, addr); err != nil {
		s.Logger.Error("handle https conn error: %v", err)
	}
}

func (s *proxyServer) parseAddr(host, port string, b []byte) (socks.Addr, error) {
	p, err := strconv.Atoi(port)
	if err != nil {
		return nil, err
	}
	if ip := net.ParseIP(host); ip == nil {
		if host == "" {
			return nil, errEmptyAddress
		}
		b[0] = socks.AddrTypeDomain
		b[1] = byte(len(host))
		copy(b[2:], []byte(host))
		n := 1 + 1 + len(host)
		b[n] = byte(p >> 8)
		b[n+1] = byte(p)
		return b[:n+2], nil
	} else {
		if ipv4 := ip.To4(); ipv4 == nil {
			ipv6 := ip.To16()
			b[0] = socks.AddrTypeIPv6
			copy(b, ipv6)
			b[1+net.IPv6len] = byte(p >> 8)
			b[1+net.IPv6len+1] = byte(p)
			return b[:1+net.IPv6len+2], nil
		} else {
			if ipv4[0] == 198 && ipv4[1] == 18 {
				addr, err := s.lookupIP(ipv4, b[:])
				addr[len(addr)-2] = byte(p >> 8)
				addr[len(addr)-1] = byte(p)
				return addr, err
			}

			b[0] = socks.AddrTypeIPv4
			copy(b, ipv4)
			b[1+net.IPv4len] = byte(p >> 8)
			b[1+net.IPv4len+1] = byte(p)
			return b[:1+net.IPv4len+2], nil
		}
	}
}
