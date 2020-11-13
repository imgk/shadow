package app

import (
	"bytes"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	_ "net/http/pprof"
	"os"
	"strconv"
	"strings"

	"github.com/miekg/dns"
	"go.uber.org/multierr"
	"go.uber.org/zap"

	"github.com/imgk/shadow/common"
)

type cmdError byte

func (e cmdError) Error() string {
	return fmt.Sprintf("socks cmd error: %v", byte(e))
}

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

func newFakeConn(conn net.Conn, reader io.Reader) fakeConn {
	return fakeConn{
		Conn:   conn,
		reader: reader,
	}
}

func (conn fakeConn) CloseRead() error {
	if close, ok := conn.Conn.(common.CloseReader); ok {
		return close.CloseRead()
	}
	return conn.Conn.Close()
}

func (conn fakeConn) CloseWrite() error {
	if close, ok := conn.Conn.(common.CloseWriter); ok {
		return close.CloseWrite()
	}
	return conn.Conn.Close()
}

func (conn fakeConn) Read(b []byte) (int, error) {
	return conn.reader.Read(b)
}

// fake common.PacketConn
type fakePacketConn struct {
	addr net.Addr
	net.PacketConn
}

func newPacketConn(src net.Addr, pc net.PacketConn) fakePacketConn {
	return fakePacketConn{
		addr:       src,
		PacketConn: pc,
	}
}

func (pc fakePacketConn) Close() error {
	return pc.PacketConn.Close()
}

func (pc fakePacketConn) RemoteAddr() net.Addr {
	return pc.addr
}

func (pc fakePacketConn) ReadTo(b []byte) (n int, addr net.Addr, err error) {
	buf := common.Get()
	defer common.Put(buf)

	n, _, err = pc.PacketConn.ReadFrom(buf)
	if err != nil {
		return
	}
	tgt, err := common.ParseAddr(buf[3:])
	if err != nil {
		return
	}
	addr = tgt
	n = copy(b, buf[3+len(tgt):n])
	return
}

func (pc fakePacketConn) WriteFrom(b []byte, addr net.Addr) (n int, err error) {
	buf := common.Get()
	defer common.Put(buf)

	src, err := common.ResolveAddrBuffer(addr, b[3:])
	if err != nil {
		return
	}
	n = copy(buf[3+len(src):], b)
	_, err = pc.PacketConn.WriteTo(buf[:3+len(src)+n], pc.addr)
	return
}

// a combined socks5/http proxy server
type proxyServer struct {
	*zap.Logger

	// Convert fake IP and handle connections
	tree    *common.DomainTree
	handler common.Handler

	// Listen
	http.Server
	netLisener net.Listener
	listener   *fakeListener

	closed chan struct{}
}

func newProxyServer(ln net.Listener, logger *zap.Logger, handler common.Handler, tree *common.DomainTree) *proxyServer {
	s := &proxyServer{
		Logger:     logger,
		tree:       tree,
		handler:    handler,
		netLisener: ln,
		listener:   newFakeListener(ln.Addr()),
		closed:     make(chan struct{}),
	}
	s.Server.Handler = http.Handler(s)
	return s
}

// accpet net.Conn
func (s *proxyServer) Serve() {
	go s.Server.Serve(s.listener)

	for {
		conn, err := s.netLisener.Accept()
		if err != nil {
			return
		}
		go s.handle(conn)
	}
}

// serve as a http server and http proxy server
// support GET and CONNECT method
func (s *proxyServer) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	if strings.HasPrefix(r.URL.Path, "/debug/pprof/") || r.URL.Host == "" {
		http.DefaultServeMux.ServeHTTP(w, r)
		return
	}

	switch r.Method {
	case http.MethodGet:
		s.proxyGet(w, r)
	case http.MethodConnect:
		s.proxyConnect(w, r)
	default:
		http.DefaultServeMux.ServeHTTP(w, r)
	}
}

func (s *proxyServer) Close() (err error) {
	select {
	case <-s.closed:
		return
	default:
		close(s.closed)
	}

	err = multierr.Combine(s.netLisener.Close(), s.listener.Close(), s.Server.Close())
	return
}

func (s *proxyServer) handle(conn net.Conn) {
	pc, b, ok, err := s.handshake(conn)
	if err != nil {
		if errors.Is(err, io.EOF) {
			return
		}
		s.Error(fmt.Sprintf("handshake error: %v", err))
		return
	}
	if ok {
		s.proxySocks(conn, pc, b)
		return
	}
	s.listener.Receive(newFakeConn(conn, io.MultiReader(bytes.NewReader(b), conn)))
}

func (s *proxyServer) LookupIP(ip net.IP, b []byte) (common.Addr, error) {
	option := s.tree.Load(fmt.Sprintf("%d.%d.18.198.in-addr.arpa.", ip[3], ip[2]))
	if rr, ok := option.(*dns.PTR); ok {
		b[0] = common.AddrTypeDomain
		b[1] = byte(len(rr.Ptr))
		n := copy(b[2:], rr.Ptr[:])
		return b[:2+n+2], nil
	}
	return nil, errors.New("fake ip address not found")
}

// handshake
func (s *proxyServer) handshake(conn net.Conn) (pc net.PacketConn, tgt []byte, ok bool, err error) {
	b := [3 + common.MaxAddrLen]byte{}
	// read socks5 header
	if _, err = io.ReadFull(conn, b[:2]); err != nil {
		return
	}
	if b[0] != 0x05 {
		ok = false
		tgt = make([]byte, 2)
		copy(tgt, b[:2])
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
		err = cmdError(b[1])
		return
	}

	bb := make([]byte, common.MaxAddrLen)
	tgt, err = common.ReadAddrBuffer(conn, bb)
	if err != nil {
		return
	}
	if bb[0] == common.AddrTypeIPv4 {
		if bb[1] == 198 && bb[2] == 18 {
			p1 := bb[1+net.IPv4len]
			p2 := bb[1+net.IPv4len+1]
			tgt, err = s.LookupIP(net.IP(bb[1:1+net.IPv4len]), bb)
			if err != nil {
				return
			}
			tgt[len(tgt)-2] = p1
			tgt[len(tgt)-1] = p2
		}
	}

	// write back address
	addr := common.Addr{}
	switch b[1] {
	case 0x01:
		addr, err = common.ResolveAddrBuffer(conn.LocalAddr(), b[3:])
	case 0x03:
		addr, err = common.ResolveAddrBuffer(pc.LocalAddr(), b[3:])
	}
	if err != nil {
		return
	}
	b[1] = 0x00
	_, err = conn.Write(b[:3+len(addr)])
	return
}

// handle socks5 proxy
func (s *proxyServer) proxySocks(conn net.Conn, pc net.PacketConn, addr common.Addr) {
	defer conn.Close()

	if pc != nil {
		defer pc.Close()

		src, err := common.ResolveUDPAddr(addr)
		if err != nil {
			s.Error(fmt.Sprintf("resolve udp addr error: %v", err))
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
				pc.Close()
			}
		}(conn, pc)

		s.Info(fmt.Sprintf("proxyd %v <-UDP-> all", addr))
		if err := s.handler.HandlePacket(newPacketConn(src, pc)); err != nil {
			s.Error(fmt.Sprintf("handle udp error: %v", err))
		}
		return
	}

	s.Info(fmt.Sprintf("proxyd %v <-TCP-> %v", conn.RemoteAddr(), addr))
	if err := s.handler.Handle(conn, addr); err != nil {
		s.Error(fmt.Sprintf("handle tcp error: %v", err))
	}
}

// handle http proxy GET
func (s *proxyServer) proxyGet(w http.ResponseWriter, r *http.Request) {
	b := [common.MaxAddrLen]byte{}
	addr, err := s.ParseAddr(r.URL.Host, "80", b[:])
	if err != nil {
		if errors.Is(err, errors.New("address error")) {
			return
		}
		s.Error(fmt.Sprintf("parse url host error: %v", err))
		return
	}

	src, dst := net.Pipe()
	t := http.Transport{
		Dial: func(network, addr string) (net.Conn, error) {
			return src, nil
		},
	}
	defer dst.Close()

	s.Info(fmt.Sprintf("proxyd %v <-TCP-> %v", r.RemoteAddr, addr))
	go s.Handle(dst, addr)

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

	if _, err := common.Copy(w, resp.Body); err != nil {
		if errors.Is(err, io.EOF) {
			return
		}
		s.Error(fmt.Sprintf("copy response body error: %v", err))
	}
}

func (s *proxyServer) Handle(conn net.Conn, addr net.Addr) {
	if err := s.handler.Handle(conn, addr); err != nil {
		s.Error(fmt.Sprintf("handle http conn error: %v", err))
	}
}

// handle http proxy CONNECT
func (s *proxyServer) proxyConnect(w http.ResponseWriter, r *http.Request) {
	host, port, _ := net.SplitHostPort(r.URL.Host)

	b := [common.MaxAddrLen]byte{}
	addr, err := s.ParseAddr(host, port, b[:])
	if err != nil {
		s.Error(fmt.Sprintf("parse url host error: %v", err))
		return
	}

	rw, ok := w.(http.Hijacker)
	if !ok {
		s.Error("not a http.Hijacker")
		return
	}
	conn, _, err := rw.Hijack()
	if err != nil {
		s.Error(fmt.Sprintf("http hijack error: %v", err))
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}
	conn.Write([]byte("HTTP/1.1 200 Connection Established\r\n\r\n"))

	s.Info(fmt.Sprintf("proxyd %v <-TCP-> %v", conn.RemoteAddr(), addr))
	if err := s.handler.Handle(conn, addr); err != nil {
		s.Error(fmt.Sprintf("handle https conn error: %v", err))
	}
}

func (s *proxyServer) ParseAddr(host, port string, b []byte) (common.Addr, error) {
	p, err := strconv.Atoi(port)
	if err != nil {
		return nil, err
	}
	if ip := net.ParseIP(host); ip == nil {
		if host == "" {
			return nil, errors.New("nil address error")
		}
		b[0] = common.AddrTypeDomain
		b[1] = byte(len(host))
		copy(b[2:], []byte(host))
		n := 1 + 1 + len(host)
		b[n] = byte(p >> 8)
		b[n+1] = byte(p)
		return b[:n+2], nil
	} else {
		if ipv4 := ip.To4(); ipv4 == nil {
			ipv6 := ip.To16()
			b[0] = common.AddrTypeIPv6
			copy(b, ipv6)
			b[1+net.IPv6len] = byte(p >> 8)
			b[1+net.IPv6len+1] = byte(p)
			return b[:1+net.IPv6len+2], nil
		} else {
			if ipv4[0] == 198 && ipv4[1] == 18 {
				addr, err := s.LookupIP(ipv4, b[:])
				addr[len(addr)-2] = byte(p >> 8)
				addr[len(addr)-1] = byte(p)
				return addr, err
			}

			b[0] = common.AddrTypeIPv4
			copy(b, ipv4)
			b[1+net.IPv4len] = byte(p >> 8)
			b[1+net.IPv4len+1] = byte(p)
			return b[:1+net.IPv4len+2], nil
		}
	}
}
