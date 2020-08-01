package utils

import (
	"bytes"
	"context"
	"crypto/tls"
	"encoding/base64"
	"encoding/binary"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/url"
	"time"
)

type Dialer struct {
	net.Dialer
	server string
	Config *tls.Config
}

func (d *Dialer) Dial(network, addr string) (net.Conn, error) {
	conn, err := d.Dialer.Dial("tcp", d.server)
	if nc, ok := conn.(*net.TCPConn); ok {
		nc.SetKeepAlive(true)
	}
	return conn, err
}

func (d *Dialer) DialContext(ctx context.Context, network, addr string) (net.Conn, error) {
	conn, err := d.Dialer.DialContext(ctx, "tcp", d.server)
	if nc, ok := conn.(*net.TCPConn); ok {
		nc.SetKeepAlive(true)
	}
	return conn, err
}

func (d *Dialer) DialTLS(network, addr string) (net.Conn, error) {
	conn, err := d.Dialer.Dial("tcp", d.server)
	if err != nil {
		return nil, err
	}
	if nc, ok := conn.(*net.TCPConn); ok {
		nc.SetKeepAlive(true)
	}
	return tls.Client(conn, d.Config), err
}

func (d *Dialer) DialTLSContext(ctx context.Context, network, addr string) (net.Conn, error) {
	conn, err := d.Dialer.DialContext(ctx, "tcp", d.server)
	if err != nil {
		return nil, err
	}
	if nc, ok := conn.(*net.TCPConn); ok {
		nc.SetKeepAlive(true)
	}
	return tls.Client(conn, d.Config), nil
}

type Resolver interface {
	Resolve([]byte, int) (int, error)
	DialContext(ctx context.Context, network, address string) (net.Conn, error)
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
			Addr:    addr.String(),
			Timeout: time.Second * 3,
		}
		return resolver, nil
	case "tls":
		addr, err := net.ResolveTCPAddr("tcp", net.JoinHostPort(u.Host, "853"))
		if err != nil {
			return nil, err
		}

		resolver := &TLSResolver{
			Conf: &tls.Config{
				ServerName:         u.Host,
				ClientSessionCache: tls.NewLRUClientSessionCache(32),
				InsecureSkipVerify: false,
			},
			Addr:    addr.String(),
			Timeout: time.Second * 3,
		}
		return resolver, nil
	case "https":
		addr, err := net.ResolveTCPAddr("tcp", net.JoinHostPort(u.Host, "443"))
		if err != nil {
			return nil, err
		}

		resolver := &HTTPSResolverPost{
			Dialer: Dialer{
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
	Dialer  net.Dialer
	Addr    string
	Timeout time.Duration
}

func (r *UDPResolver) Resolve(b []byte, n int) (int, error) {
	conn, err := net.Dial("udp", r.Addr)
	if err != nil {
		return 0, err
	}
	defer conn.Close()

	_, err = conn.Write(b[2 : 2+n])
	if err != nil {
		return 0, err
	}

	conn.SetReadDeadline(time.Now().Add(r.Timeout))
	return conn.Read(b[2:])
}

func (r *UDPResolver) DialContext(ctx context.Context, network, address string) (net.Conn, error) {
	return r.Dialer.DialContext(ctx, "udp", r.Addr)
}

type TCPResolver struct {
	Dialer  net.Dialer
	Addr    string
	Timeout time.Duration
}

func (r *TCPResolver) Resolve(b []byte, n int) (l int, err error) {
	binary.BigEndian.PutUint16(b[:2], uint16(n))

	conn, err := net.Dial("tcp", r.Addr)
	if err != nil {
		return
	}
	conn.(*net.TCPConn).SetKeepAlive(true)
	defer conn.Close()

	_, err = conn.Write(b[:2+n])
	if err != nil {
		return
	}

	conn.SetReadDeadline(time.Now().Add(r.Timeout))
	_, err = io.ReadFull(conn, b[:2])
	if err != nil {
		return
	}

	l = int(binary.BigEndian.Uint16(b[:2]))
	if l > len(b)-2 {
		err = io.ErrShortBuffer
		return
	}

	_, err = io.ReadFull(conn, b[2:2+l])
	return
}

func (r *TCPResolver) DialContext(ctx context.Context, network, address string) (net.Conn, error) {
	conn, err := r.Dialer.DialContext(ctx, "tcp", r.Addr)
	if nc, ok := conn.(*net.TCPConn); ok {
		nc.SetKeepAlive(true)
	}
	return conn, err
}

type TLSResolver struct {
	Dialer  net.Dialer
	Conf    *tls.Config
	Addr    string
	Timeout time.Duration
}

func (r *TLSResolver) Resolve(b []byte, n int) (l int, err error) {
	binary.BigEndian.PutUint16(b[:2], uint16(n))

	conn, err := net.Dial("tcp", r.Addr)
	if err != nil {
		return
	}
	conn.(*net.TCPConn).SetKeepAlive(true)
	conn = tls.Client(conn, r.Conf)
	defer conn.Close()

	_, err = conn.Write(b[:2+n])
	if err != nil {
		return
	}

	conn.SetReadDeadline(time.Now().Add(r.Timeout))
	_, err = io.ReadFull(conn, b[:2])
	if err != nil {
		return
	}

	l = int(binary.BigEndian.Uint16(b[:2]))
	if l > len(b)-2 {
		err = io.ErrShortBuffer
		return
	}

	_, err = io.ReadFull(conn, b[2:2+l])
	return
}

func (r *TLSResolver) DialContext(ctx context.Context, network, address string) (net.Conn, error) {
	conn, err := r.Dialer.DialContext(ctx, "tcp", r.Addr)
	if nc, ok := conn.(*net.TCPConn); ok {
		nc.SetKeepAlive(true)
		conn = tls.Client(conn, r.Conf)
	}
	return conn, err
}

type Buffer []byte

func (b Buffer) ReadFrom(r io.Reader) (n int64, err error) {
	for {
		nr, er := r.Read(b[n:])
		if nr > 0 {
			n += int64(nr)
		}
		if er != nil {
			if errors.Is(er, io.EOF) {
				break
			}
			err = er
			break
		}
		if int(n) == len(b) {
			err = io.ErrShortBuffer
			break
		}
	}
	return
}

type Conn struct{}

func (c Conn) Close() error                       { return nil }
func (c Conn) LocalAddr() net.Addr                { return nil }
func (c Conn) RemoteAddr() net.Addr               { return nil }
func (c Conn) SetDeadline(t time.Time) error      { return nil }
func (c Conn) SetReadDeadline(t time.Time) error  { return nil }
func (c Conn) SetWriteDeadline(t time.Time) error { return nil }

type PacketConnPost struct {
	Conn
	r  *HTTPSResolverPost
	rc io.ReadCloser
}

func (c *PacketConnPost) Write(b []byte) (int, error) {
	req, err := http.NewRequest(http.MethodPost, c.r.BaseUrl, bytes.NewBuffer(b))
	if err != nil {
		return 0, err
	}
	req.Header.Add("accept", "application/dns-message")
	req.Header.Add("content-type", "application/dns-message")

	res, err := c.r.Do(req)
	if err != nil {
		return 0, err
	}
	if res.StatusCode != http.StatusOK {
		res.Body.Close()
		return 0, fmt.Errorf("bad http response code: %v", res.StatusCode)
	}

	c.rc = res.Body
	return len(b), err
}

func (c *PacketConnPost) WriteTo(b []byte, addr net.Addr) (int, error) {
	return c.Write(b)
}

func (c *PacketConnPost) Read(b []byte) (int, error) {
	n, err := Buffer(b).ReadFrom(c.rc)
	c.rc.Close()
	return int(n), err
}

func (c *PacketConnPost) ReadFrom(b []byte) (int, net.Addr, error) {
	n, err := c.Read(b)
	return n, nil, err
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

	nr, err := Buffer(b[2:]).ReadFrom(res.Body)
	return int(nr), err
}

func (r *HTTPSResolverPost) DialContext(ctx context.Context, network, address string) (net.Conn, error) {
	return &PacketConnPost{r: r}, nil
}

type PacketConnGet struct {
	Conn
	r  *HTTPSResolverGet
	rc io.ReadCloser
}

func (c *PacketConnGet) Write(b []byte) (int, error) {
	req, err := http.NewRequest(http.MethodGet, fmt.Sprintf("%s?%s=%s", c.r.BaseUrl, "dns", base64.RawURLEncoding.EncodeToString(b)), nil)
	if err != nil {
		return 0, err
	}
	req.Header.Add("accept", "application/dns-message")
	req.Header.Add("content-type", "application/dns-message")

	res, err := c.r.Do(req)
	if err != nil {
		return 0, err
	}
	if res.StatusCode != http.StatusOK {
		res.Body.Close()
		return 0, fmt.Errorf("bad http response code: %v", res.StatusCode)
	}
	c.rc = res.Body
	return len(b), err
}

func (c *PacketConnGet) WriteTo(b []byte, addr net.Addr) (int, error) {
	return c.Write(b)
}

func (c *PacketConnGet) Read(b []byte) (int, error) {
	n, err := Buffer(b).ReadFrom(c.rc)
	c.rc.Close()
	return int(n), err
}

func (c *PacketConnGet) ReadFrom(b []byte) (int, net.Addr, error) {
	n, err := c.Read(b)
	return n, nil, err
}

type HTTPSResolverGet struct {
	Dialer  Dialer
	BaseUrl string
	Timeout time.Duration
	http.Client
}

func (r *HTTPSResolverGet) Resolve(b []byte, n int) (int, error) {
	req, err := http.NewRequest(http.MethodGet, fmt.Sprintf("%s?%s=%s", r.BaseUrl, "dns", base64.RawURLEncoding.EncodeToString(b[2:2+n])), nil)
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

	nr, err := Buffer(b[2:]).ReadFrom(res.Body)
	return int(nr), err
}

func (r *HTTPSResolverGet) DialContext(ctx context.Context, network, address string) (net.Conn, error) {
	return &PacketConnGet{r: r}, nil
}
