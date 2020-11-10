package app

import (
	"bytes"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"strconv"

	"github.com/miekg/dns"
	"go.uber.org/zap"

	"github.com/imgk/shadow/common"
)

var (
	errClosed    = errors.New("closed")
	errNotFound  = errors.New("not found")
	errEmptyAddr = errors.New("address error")
)

var success = [...]byte{'H', 'T', 'T', 'P', '/', '1', '.', '1', ' ', '2', '0', '0', ' ', 'C', 'o', 'n', 'n', 'e', 'c', 't', 'i', 'o', 'n', ' ', 'E', 's', 't', 'a', 'b', 'l', 'i', 's', 'h', 'e', 'd', '\r', '\n', '\r', '\n'}

var errAuth = errors.New("no authentication supported")

type CmdError byte

func (e CmdError) Error() string {
	return fmt.Sprintf("socks cmd error: %v", byte(e))
}

type fakeListener struct {
	closed chan struct{}
	conn   chan net.Conn
	addr   net.Addr
}

func (s *fakeListener) Accept() (net.Conn, error) {
	select {
	case <-s.closed:
	case conn := <-s.conn:
		return conn, nil
	}
	return nil, errClosed
}

func (s *fakeListener) receive(conn net.Conn) {
	select {
	case <-s.closed:
	case s.conn <- conn:
	}
}

func (s *fakeListener) Close() error {
	select {
	case <-s.closed:
		return nil
	default:
		if s.closed != nil {
			close(s.closed)
		}
	}
	return nil
}

func (s fakeListener) Addr() net.Addr {
	return s.addr
}

type fakeConn struct {
	net.Conn
	reader io.Reader
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

type fakePacketConn struct {
	rBuf []byte
	wBuf []byte
	addr net.Addr
	net.PacketConn
}

func newPacketConn(src net.Addr, pc net.PacketConn) *fakePacketConn {
	return &fakePacketConn{
		rBuf:       common.Get(),
		wBuf:       common.Get(),
		addr:       src,
		PacketConn: pc,
	}
}

func (pc *fakePacketConn) Close() error {
	common.Put(pc.rBuf)
	common.Put(pc.wBuf)
	return pc.PacketConn.Close()
}

func (pc *fakePacketConn) RemoteAddr() net.Addr {
	return pc.addr
}

func (pc *fakePacketConn) ReadTo(b []byte) (n int, addr net.Addr, err error) {
	n, _, err = pc.PacketConn.ReadFrom(pc.rBuf)
	if err != nil {
		return
	}
	tgt, err := common.ParseAddr(pc.rBuf[3:])
	if err != nil {
		return
	}
	addr = tgt
	n = copy(b, pc.rBuf[3+len(tgt):n])
	return
}

func (pc *fakePacketConn) WriteFrom(b []byte, addr net.Addr) (n int, err error) {
	src, err := common.ResolveAddrBuffer(addr, b[3:])
	if err != nil {
		return
	}
	n = copy(pc.wBuf[3+len(src):], b)
	_, err = pc.PacketConn.WriteTo(pc.wBuf[:3+len(src)+n], pc.addr)
	return
}

type proxyServer struct {
	*zap.Logger
	router   http.Handler
	handler  common.Handler
	listener fakeListener
	server   http.Server
	tree     *common.DomainTree
	closed   bool
}

func (s *proxyServer) Serve(ln net.Listener) {
	s.listener.closed = make(chan struct{})
	s.listener.conn = make(chan net.Conn, 5)
	s.listener.addr = ln.Addr()
	s.server.Handler = s.router
	s.closed = false

	go s.server.Serve(&s.listener)

	for {
		conn, err := ln.Accept()
		if err != nil {
			if s.closed {
				return
			}
			s.Error(fmt.Sprintf("accept conns error: %v", err))
			return
		}
		go s.handle(conn)
	}
}

func (s *proxyServer) Close() error {
	if s.closed {
		return nil
	}
	s.closed = true
	s.listener.Close()
	s.server.Close()
	return nil
}

func (s *proxyServer) handle(conn net.Conn) {
	pc, b, ok, err := s.handshake(conn)
	if err != nil {
		s.Error(fmt.Sprintf("handshake error: %v", err))
		return
	}
	if ok {
		s.proxySocks(conn, pc, b)
		return
	}
	conn = fakeConn{
		Conn:   conn,
		reader: io.MultiReader(bytes.NewReader(b), conn),
	}
	s.listener.receive(conn)
}

func (s *proxyServer) LookupIP(ip net.IP, b []byte) (common.Addr, error) {
	option := s.tree.Load(fmt.Sprintf("%d.%d.18.198.in-addr.arpa.", ip[3], ip[2]))
	if rr, ok := option.(*dns.PTR); ok {
		b[0] = common.AddrTypeDomain
		b[1] = byte(len(rr.Ptr))
		n := copy(b[2:], rr.Ptr[:])
		return b[:2+n+2], nil
	}
	return nil, errNotFound
}

func (s *proxyServer) handshake(conn net.Conn) (pc net.PacketConn, tgt []byte, ok bool, err error) {
	b := [3 + common.MaxAddrLen]byte{}
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
	if _, err = io.ReadFull(conn, b[2:2+b[1]]); err != nil {
		return
	}
	err = errAuth
	for _, v := range b[2 : 2+b[1]] {
		if v == 0 {
			err = nil
			break
		}
	}
	if err != nil {
		return
	}

	if _, err = conn.Write([]byte{0x05, 0x00}); err != nil {
		return
	}

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
	default:
		err = CmdError(b[1])
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

func (s *proxyServer) proxySocks(conn net.Conn, pc net.PacketConn, addr common.Addr) {
	defer conn.Close()

	if pc != nil {
		defer pc.Close()

		src, err := common.ResolveUDPAddr(addr)
		if err != nil {
			s.Error(fmt.Sprintf("resolve udp addr error: %v", err))
			return
		}

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

func (s *proxyServer) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	switch r.Method {
	case http.MethodGet:
		s.proxyGet(w, r)
	case http.MethodConnect:
		s.proxyConnect(w, r)
	default:
		w.WriteHeader(http.StatusForbidden)
	}
}

func (s *proxyServer) proxyGet(w http.ResponseWriter, r *http.Request) {
	b := [common.MaxAddrLen]byte{}
	addr, err := s.ParseAddr(r.URL.Host, "80", b[:])
	if err != nil {
		if errors.Is(err, errEmptyAddr) {
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
		s.Error("not a http.Hijack")
		return
	}
	conn, _, err := rw.Hijack()
	if err != nil {
		s.Error(fmt.Sprintf("http hijack error: %v", err))
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}
	conn.Write(success[:])

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
			return nil, errEmptyAddr
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
			if ip[0] == 198 && ip[1] == 18 {
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
