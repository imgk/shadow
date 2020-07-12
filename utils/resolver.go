package utils

import (
	"bytes"
	"context"
	"crypto/tls"
	"encoding/base64"
	"encoding/binary"
	"fmt"
	"io"
	"io/ioutil"
	"net"
	"net/http"
	"net/url"
	"sync"
	"time"
)

type Dialer struct {
	net.Dialer
	server string
	Config *tls.Config
}

func (d *Dialer) Dial(network, addr string) (net.Conn, error) {
	conn, err := d.Dialer.Dial("tcp", d.server)
	if err != nil {
		return nil, err
	}

	conn.(*net.TCPConn).SetKeepAlive(true)
	return conn, nil
}

func (d *Dialer) DialContext(ctx context.Context, network, addr string) (net.Conn, error) {
	conn, err := d.Dialer.DialContext(ctx, "tcp", d.server)
	if err != nil {
		return nil, err
	}

	conn.(*net.TCPConn).SetKeepAlive(true)
	return conn, nil
}

func (d *Dialer) DialTLS(network, addr string) (net.Conn, error) {
	conn, err := d.Dialer.Dial("tcp", d.server)
	if err != nil {
		return nil, err
	}

	conn.(*net.TCPConn).SetKeepAlive(true)
	return tls.Client(conn, d.Config), nil
}

func (d *Dialer) DialTLSContext(ctx context.Context, network, addr string) (net.Conn, error) {
	conn, err := d.Dialer.DialContext(ctx, "tcp", d.server)
	if err != nil {
		return nil, err
	}

	conn.(*net.TCPConn).SetKeepAlive(true)
	return tls.Client(conn, d.Config), nil
}

type Resolver interface {
	Resolve([]byte, int) (int, error)
	Stop()
}

func NewResolver(s string) (Resolver, error) {
	u, err := url.Parse(s)
	if err != nil {
		return nil, fmt.Errorf("parse url %v error: %v", s, err)
	}

	switch u.Scheme {
	case "udp":
		addr, err := net.ResolveUDPAddr("udp", net.JoinHostPort(u.Host, "53"))
		if err != nil {
			return nil, err
		}

		resolver := &UDPResolver{
			Addr:    addr.String(),
			Timeout: time.Second * 3,
		}
		return resolver, nil
	case "tcp":
		addr, err := net.ResolveTCPAddr("tcp", net.JoinHostPort(u.Host, "53"))
		if err != nil {
			return nil, err
		}

		resolver := &TCPResolver{
			Mutex:   sync.Mutex{},
			Ticker:  time.NewTicker(time.Minute),
			Addr:    addr.String(),
			Timeout: time.Second * 3,
			conns:   make(map[net.Conn]time.Time),
		}
		go resolver.CleanLoop()
		return resolver, nil
	case "tls":
		addr, err := net.ResolveTCPAddr("tcp", net.JoinHostPort(u.Host, "853"))
		if err != nil {
			return nil, err
		}

		resolver := &TLSResolver{
			Mutex:  sync.Mutex{},
			Ticker: time.NewTicker(time.Minute),
			Conf: &tls.Config{
				ServerName:         u.Host,
				ClientSessionCache: tls.NewLRUClientSessionCache(32),
				InsecureSkipVerify: false,
			},
			Addr:    addr.String(),
			Timeout: time.Second * 3,
			conns:   make(map[net.Conn]time.Time),
		}
		go resolver.CleanLoop()
		return resolver, nil
	case "https":
		addr, err := net.ResolveTCPAddr("tcp", net.JoinHostPort(u.Host, "443"))
		if err != nil {
			return nil, err
		}

		resolver := &HTTPSResolverPost{
			Dialer:  Dialer{
				Dialer: net.Dialer{},
				server: addr.String(),
				Config: &tls.Config{
					ServerName:         u.Host,
					ClientSessionCache: tls.NewLRUClientSessionCache(32),
					InsecureSkipVerify: false,
				},
			},
			BaseUrl: s,
			Timeout: time.Second * 3,
			Client: http.Client{
				Timeout: time.Second * 3,
			},
		}
		resolver.Client.Transport = &http.Transport{
			Dial:              resolver.Dialer.Dial,
			DialContext:       resolver.Dialer.DialContext,
			TLSClientConfig:   resolver.Dialer.Config,
			DialTLS:           resolver.Dialer.DialTLS,
			DialTLSContext:    resolver.Dialer.DialTLSContext,
			ForceAttemptHTTP2: true,
		}
		return resolver, nil
	default:
		return nil, fmt.Errorf("not a valid dns protocol")
	}
}

type UDPResolver struct {
	Addr    string
	Timeout time.Duration
}

func (r *UDPResolver) Resolve(b []byte, n int) (int, error) {
	conn, err := net.Dial("udp", r.Addr)
	if err != nil {
		return 0, err
	}
	defer conn.Close()

	_, err = conn.Write(b[2:2+n])
	if err != nil {
		return 0, err
	}

	err = conn.SetReadDeadline(time.Now().Add(r.Timeout))
	if err != nil {
		return 0, err
	}

	n, err = conn.Read(b[2:])
	if err != nil {
		return 0, err
	}

	return n, nil
}

func (r *UDPResolver) Stop() {}

type TCPResolver struct {
	sync.Mutex
	Ticker  *time.Ticker
	Addr    string
	Timeout time.Duration
	conns   map[net.Conn]time.Time
}

func (r *TCPResolver) Get() net.Conn {
	r.Lock()
	for conn, _ := range r.conns {
		delete(r.conns, conn)
		r.Unlock()
		return conn
	}
	r.Unlock()
	return nil
}

func (r *TCPResolver) Put(conn net.Conn) {
	r.Lock()
	r.conns[conn] = time.Now()
	r.Unlock()
}

func (r *TCPResolver) CleanLoop() {
	for now := range r.Ticker.C {
		r.Lock()
		for conn, t := range r.conns {
			if now.Sub(t) > time.Minute*3 {
				delete(r.conns, conn)
				conn.Close()
			}
		}
		r.Unlock()
	}
}

func (r *TCPResolver) Resolve(b []byte, n int) (m int, err error) {
	binary.BigEndian.PutUint16(b[:2], uint16(n))
	id := binary.BigEndian.Uint16(b[2:4])
	conn := r.Get()
	defer func() {
		if err == nil {
			r.Put(conn)
		}
	}()
	for newc := true; newc; {
		if conn == nil {
			newc = false
			c, err := net.Dial("tcp", r.Addr)
			if err != nil {
				return 0, err
			}
			c.(*net.TCPConn).SetKeepAlive(true)
			conn = c
		}

		_, err := conn.Write(b[:2+n])
		if err != nil {
			conn.Close()
			conn = r.Get()
			continue
		}

		conn.SetReadDeadline(time.Now().Add(r.Timeout))
		_, err = io.ReadFull(conn, b[:2])
		if err != nil {
			if ne, ok := err.(net.Error); ok {
				if ne.Timeout() {
					return 0, err
				}
			}
			conn.Close()
			conn = r.Get()
			continue
		}

		n, err = io.ReadFull(conn, b[2:2+binary.BigEndian.Uint16(b[:2])])
		if err != nil {
			return 0, err
		}

		if id == binary.BigEndian.Uint16(b[2:4]) {
			return n, nil
		}
	}
	return n, nil
}

func (r *TCPResolver) Stop() {
	r.Ticker.Stop()
}

type TLSResolver struct {
	sync.Mutex
	Ticker  *time.Ticker
	Conf    *tls.Config
	Addr    string
	Timeout time.Duration
	conns   map[net.Conn]time.Time
}

func (r *TLSResolver) Get() net.Conn {
	r.Lock()
	for conn, _ := range r.conns {
		delete(r.conns, conn)
		r.Unlock()
		return conn
	}
	r.Unlock()
	return nil
}

func (r *TLSResolver) Put(conn net.Conn) {
	r.Lock()
	r.conns[conn] = time.Now()
	r.Unlock()
}

func (r *TLSResolver) CleanLoop() {
	for now := range r.Ticker.C {
		r.Lock()
		for conn, t := range r.conns {
			if now.Sub(t) > time.Minute*3 {
				delete(r.conns, conn)
				conn.Close()
			}
		}
		r.Unlock()
	}
}

func (r *TLSResolver) Resolve(b []byte, n int) (m int, err error) {
	binary.BigEndian.PutUint16(b[:2], uint16(n))
	id := binary.BigEndian.Uint16(b[2:4])
	conn := r.Get()
	defer func() {
		if err == nil {
			r.Put(conn)
		}
	}()
	for newc := true; newc; {
		if conn == nil {
			newc = false
			c, err := net.Dial("tcp", r.Addr)
			if err != nil {
				return 0, err
			}
			c.(*net.TCPConn).SetKeepAlive(true)
			conn = tls.Client(c, r.Conf)
		}

		_, err := conn.Write(b[:2+n])
		if err != nil {
			conn.Close()
			conn = r.Get()
			continue
		}

		conn.SetReadDeadline(time.Now().Add(r.Timeout))
		_, err = io.ReadFull(conn, b[:2])
		if err != nil {
			if ne, ok := err.(net.Error); ok {
				if ne.Timeout() {
					return 0, err
				}
			}
			conn.Close()
			conn = r.Get()
			continue
		}

		n, err = io.ReadFull(conn, b[2:2+binary.BigEndian.Uint16(b[:2])])
		if err != nil {
			return 0, err
		}

		if id == binary.BigEndian.Uint16(b[2:4]) {
			return n, nil
		}
	}
	return n, nil
}

func (r *TLSResolver) Stop() {
	r.Ticker.Stop()
}

type HTTPSResolverPost struct {
	Dialer  Dialer
	BaseUrl string
	Timeout time.Duration
	http.Client
}

func (r *HTTPSResolverPost) Resolve(b []byte, n int) (int, error) {
	req, err := http.NewRequest(http.MethodPost, r.BaseUrl, bytes.NewBuffer(b[2:2+n]))
	if err != nil {
		return 0, err
	}
	req.Header.Add("accept", "application/dns-message")
	req.Header.Add("content-type", "application/dns-message")

	res, err := r.Do(req)
	if err != nil {
		return 0, err
	}
	defer res.Body.Close()

	if res.StatusCode != http.StatusOK {
		return 0, fmt.Errorf("bad http response code: %v", res.StatusCode)
	}

	msg, err := ioutil.ReadAll(res.Body)
	if err != nil {
		return 0, err
	}

	n = copy(b[2:], msg)
	if n < len(msg) {
		return n, io.ErrShortBuffer
	}

	return n, nil
}

func (r *HTTPSResolverPost) Stop() {}

type HTTPSResolverGet struct {
	Dialer  Dialer
	BaseUrl string
	Timeout time.Duration
	http.Client
}

func (r *HTTPSResolverGet) Resolve(b []byte, n int) (int, error) {
	req, err := http.NewRequest(http.MethodGet, fmt.Sprintf("%s?%s=%s", r.BaseUrl, "dns", base64.RawURLEncoding.EncodeToString(b)), nil)
	if err != nil {
		return 0, err
	}
	req.Header.Add("accept", "application/dns-message")
	req.Header.Add("content-type", "application/dns-message")

	res, err := r.Do(req)
	if err != nil {
		return 0, err
	}
	defer res.Body.Close()

	if res.StatusCode != http.StatusOK {
		return 0, fmt.Errorf("bad http response code: %v", res.StatusCode)
	}

	msg, err := ioutil.ReadAll(res.Body)
	if err != nil {
		return 0, err
	}

	n = copy(b[2:], msg)
	if n < len(msg) {
		return n, io.ErrShortBuffer
	}

	return n, nil
}

func (r *HTTPSResolverGet) Stop() {}
