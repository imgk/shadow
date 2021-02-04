package proxy

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"os"
	"strconv"
	"time"

	"github.com/imgk/shadow/pkg/gonet"
	"github.com/imgk/shadow/pkg/logger"
	"github.com/imgk/shadow/pkg/socks"
	"github.com/imgk/shadow/pkg/suffixtree"
	"github.com/imgk/shadow/pkg/xerror"
)

// Server is ...
// a combined socks5/http proxy server
type Server struct {
	// Logger is ...
	Logger logger.Logger
	// Route is ...
	Router *http.ServeMux
	// Server is ...
	// serve http.Request
	Server http.Server
	// Listener is ...
	Lisener net.Listener
	// Handler is ...
	// gonet.Handler
	Handler gonet.Handler

	// ln is ...
	ln *Listener
	// Convert fake IP and handle connections
	tree *suffixtree.DomainTree

	closed chan struct{}
}

// NewServer is ...
func NewServer(ln net.Listener, lg logger.Logger, h gonet.Handler, t *suffixtree.DomainTree, r *http.ServeMux) *Server {
	s := &Server{
		Logger:  lg,
		Router:  r,
		Lisener: ln,
		Handler: h,
		ln:      NewListener(ln.Addr()),
		tree:    t,
		closed:  make(chan struct{}),
	}
	s.Server.Handler = http.Handler(s)
	return s
}

// Serve is ...
// accept net.Conn
func (s *Server) Serve() {
	go s.Server.Serve(s.ln)

	for {
		conn, err := s.Lisener.Accept()
		if err != nil {
			return
		}
		go func(c net.Conn) {
			uc, b, ok, err := s.Handshake(c)
			if err != nil {
				s.Logger.Error("handshake error: %v", err)
				c.Close()
				return
			}
			if ok {
				s.ProxySocks(c, uc, b)
				return
			}
			s.ln.Receive(NewConn(c, bytes.NewReader(b)))
		}(conn)
	}
}

// serve as a http server and http proxy server
// support GET and CONNECT method
func (s *Server) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	if handler, pattern := s.Router.Handler(r); pattern != "" && r.URL.Host == "" {
		handler.ServeHTTP(w, r)
		return
	}

	switch r.Method {
	case http.MethodGet:
		if r.URL.Host == "" {
			http.HandlerFunc(http.NotFound).ServeHTTP(w, r)
			return
		}
		s.ProxyGet(w, r)
	case http.MethodConnect:
		s.ProxyConnect(w, r)
	default:
		http.HandlerFunc(http.NotFound).ServeHTTP(w, r)
	}
}

// Close is ...
func (s *Server) Close() error {
	select {
	case <-s.closed:
	default:
		close(s.closed)
	}
	return xerror.CombineError(s.Lisener.Close(), s.ln.Close(), s.Server.Close())
}

// Handshake is ...
func (s *Server) Handshake(conn net.Conn) (uc *net.UDPConn, buf []byte, ok bool, err error) {
	b := make([]byte, 3+socks.MaxAddrLen)

	const Ver = 0x05

	// read first two bytes to determine
	if _, err = io.ReadFull(conn, b[:2]); err != nil {
		return
	}
	if b[0] != Ver {
		ok = false
		buf = append(make([]byte, 0, 2), b[:2]...)
		return
	}

	// socks
	ok = true
	// verify authentication
	if _, err = io.ReadFull(conn, b[2:2+b[1]]); err != nil {
		return
	}
	err = errors.New("no authentication supported")
	for _, v := range b[2 : 2+b[1]] {
		if v == socks.AuthNone {
			err = nil
			break
		}
	}
	if err != nil {
		return
	}

	// write back auth method
	if _, err = conn.Write([]byte{Ver, socks.AuthNone}); err != nil {
		return
	}

	// read address
	if _, err = io.ReadFull(conn, b[:3]); err != nil {
		return
	}
	switch b[1] {
	case socks.CmdConnect:
	case socks.CmdAssociate:
	default:
		err = fmt.Errorf("socks cmd error: %v", b[1])
		return
	}

	bb := make([]byte, socks.MaxAddrLen)
	addr, err := socks.ReadAddrBuffer(conn, bb)
	if err != nil {
		return
	}

	// write back address
	switch b[1] {
	case socks.CmdConnect:
		buf = addr.Addr
		if buf[0] == socks.AddrTypeIPv4 && buf[1] == 198 && buf[2] == 18 {
			p1, p2 := buf[1+net.IPv4len], buf[1+net.IPv4len+1]
			addr, err = s.LookupIP(net.IP(buf[1:1+net.IPv4len]), bb)
			if err != nil {
				return
			}
			buf = append(addr.Addr, p1, p2)
		}
		addr, err = socks.ResolveAddrBuffer(conn.LocalAddr(), b[3:])
	case socks.CmdAssociate:
		buf = addr.Addr

		raddr := (*net.UDPAddr)(nil)
		raddr, err = socks.ResolveUDPAddr(addr)
		if err != nil {
			return
		}

		uc, err = net.DialUDP("udp", nil, raddr)
		if err != nil {
			return
		}
		defer func(c *net.UDPConn) {
			if err != nil {
				c.Close()
			}
		}(uc)
		addr, err = socks.ResolveAddrBuffer(uc.LocalAddr(), b[3:])
	}
	if err != nil {
		return
	}
	b[1] = 0x00
	_, err = conn.Write(b[:3+len(addr.Addr)])
	return
}

// ProxySocks is ...
// handle socks5 proxy
func (s *Server) ProxySocks(conn net.Conn, uc *net.UDPConn, buf []byte) {
	defer conn.Close()

	raddr := &socks.Addr{Addr: buf}
	if uc != nil {
		defer uc.Close()

		go func(conn net.Conn, uc *net.UDPConn) {
			b := make([]byte, 1)
			for {
				_, err := conn.Read(b)
				if errors.Is(err, os.ErrDeadlineExceeded) {
					break
				}
				if ne := net.Error(nil); errors.As(err, &ne) {
					if ne.Timeout() {
						continue
					}
				}
			}
			uc.SetReadDeadline(time.Now())
		}(conn, uc)

		s.Logger.Info("proxyd %v <-UDP-> all", raddr)
		if err := s.Handler.HandlePacket(NewPacketConn(raddr, uc)); err != nil {
			s.Logger.Error("handle udp error: %v", err)
		}
		conn.SetReadDeadline((time.Now()))
		return
	}

	s.Logger.Info("proxyd %v <-TCP-> %v", conn.RemoteAddr(), raddr)
	if err := s.Handler.Handle(conn, raddr); err != nil {
		s.Logger.Error("handle tcp error: %v", err)
	}
}

// ProxyGet is ...
// handle http proxy GET method
func (s *Server) ProxyGet(w http.ResponseWriter, r *http.Request) {
	b := make([]byte, socks.MaxAddrLen)
	addr, err := s.ParseAddr(r.Host, "80", b)
	if err != nil {
		s.Logger.Error("parse url host error: %v", err)
		return
	}

	src, dst := net.Pipe()
	t := http.Transport{
		Dial: func(network, addr string) (net.Conn, error) {
			return src, nil
		},
		DialContext: func(ctx context.Context, network, addr string) (net.Conn, error) {
			return src, nil
		},
	}
	defer dst.Close()

	s.Logger.Info("proxyd %v <-TCP-> %v", r.RemoteAddr, addr)
	go func(conn net.Conn, addr net.Addr) {
		if err := s.Handler.Handle(conn, addr); err != nil {
			s.Logger.Error("handle http conn error: %v", err)
		}
	}(dst, addr)

	resp, err := t.RoundTrip(r)
	if err != nil {
		return
	}
	defer resp.Body.Close()

	for k, v := range resp.Header {
		for _, vv := range v {
			w.Header().Add(k, vv)
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

// ProxyConnect is ...
// handle http proxy CONNECT method
func (s *Server) ProxyConnect(w http.ResponseWriter, r *http.Request) {
	host, port, err := net.SplitHostPort(r.Host)
	if err != nil {
		s.Logger.Error("split host port error: %v", err)
		return
	}

	b := make([]byte, socks.MaxAddrLen)
	addr, err := s.ParseAddr(host, port, b)
	if err != nil {
		s.Logger.Error("parse url host error: %v", err)
		return
	}

	rw, ok := w.(http.Hijacker)
	if !ok {
		s.Logger.Error("not a http.Hijacker")
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}
	conn, _, err := rw.Hijack()
	if err != nil {
		s.Logger.Error("http hijack error: %v", err)
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}
	if _, err := io.WriteString(conn, "HTTP/1.1 200 Connection Established\r\n\r\n"); err != nil {
		s.Logger.Error("write response error: %v", err)
		return
	}

	s.Logger.Info("proxyd %v <-TCP-> %v", conn.RemoteAddr(), addr)
	if err := s.Handler.Handle(conn, addr); err != nil {
		s.Logger.Error("handle https conn error: %v", err)
	}
}

// LookupIP is ...
func (s *Server) LookupIP(ip net.IP, b []byte) (*socks.Addr, error) {
	ss := fmt.Sprintf("%d.%d.18.198.in-addr.arpa.", ip[3], ip[2])
	if de, ok := s.tree.Load(ss).(*suffixtree.DomainEntry); ok {
		b = append(append(b[:0], socks.AddrTypeDomain, byte(len(de.PTR.Ptr))), de.PTR.Ptr[:]...)
		return &socks.Addr{Addr: b}, nil
	}
	return nil, errors.New("not found")
}

// ParseAddr is ...
func (s *Server) ParseAddr(host, port string, b []byte) (*socks.Addr, error) {
	if host == "" || port == "" {
		return nil, errors.New("nil address or port error")
	}

	prt, err := strconv.Atoi(port)
	if err != nil {
		return nil, err
	}

	ip := net.ParseIP(host)
	if ip == nil {
		b = append(append(b[:0], socks.AddrTypeDomain, byte(len(host))), host[:]...)
		return &socks.Addr{Addr: append(b, byte(prt>>8), byte(prt))}, nil
	}

	ipv4 := ip.To4()
	if ipv4 == nil {
		b = append(append(b[:0], socks.AddrTypeIPv6), ip.To16()...)
		return &socks.Addr{Addr: append(b, byte(prt>>8), byte(prt))}, nil
	}

	if ipv4[0] == 198 && ipv4[1] == 18 {
		sAddr, err := s.LookupIP(ipv4, b)
		if err != nil {
			return nil, err
		}
		sAddr.Addr = append(sAddr.Addr, byte(prt>>8), byte(prt))
		return sAddr, nil
	}

	b = append(append(b[:0], socks.AddrTypeIPv4), ipv4...)
	return &socks.Addr{Addr: append(b, byte(prt>>8), byte(prt))}, nil
}
