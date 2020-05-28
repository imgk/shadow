package dns

import (
	"bytes"
	"context"
	"crypto/tls"
	"encoding/base64"
	"encoding/binary"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/url"
	"time"
)

type Resolver interface {
	Resolve([]byte, int) (int, error)
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

		return &UDPResolver{
			Addr:    addr.String(),
			Timeout: time.Second * 3,
		}, nil
	case "tcp":
		addr, err := net.ResolveTCPAddr("tcp", net.JoinHostPort(u.Host, "53"))
		if err != nil {
			return nil, err
		}

		return &TCPResolver{
			Addr:    addr.String(),
			Timeout: time.Second * 3,
		}, nil
	case "tls":
		addr, err := net.ResolveTCPAddr("tcp", net.JoinHostPort(u.Host, "853"))
		if err != nil {
			return nil, err
		}

		return &TLSResolver{
			Conf: &tls.Config{
				ServerName:         u.Host,
				ClientSessionCache: tls.NewLRUClientSessionCache(32),
				InsecureSkipVerify: false,
			},
			Addr:    addr.String(),
			Timeout: time.Second * 3,
		}, nil
	case "https":
		addr, err := net.ResolveTCPAddr("tcp", net.JoinHostPort(u.Host, "443"))
		if err != nil {
			return nil, err
		}

		server := addr.String()
		dialer := &net.Dialer{}
		config := &tls.Config{
			ServerName:         u.Host,
			ClientSessionCache: tls.NewLRUClientSessionCache(32),
			InsecureSkipVerify: false,
		}

		transport := &http.Transport{
			Dial: func(network, addr string) (net.Conn, error) {
				conn, err := dialer.Dial("tcp", server)
				if err != nil {
					return nil, err
				}

				conn.(*net.TCPConn).SetKeepAlive(true)
				return conn, nil
			},
			DialContext: func(ctx context.Context, network, addr string) (net.Conn, error) {
				conn, err := dialer.DialContext(ctx, "tcp", server)
				if err != nil {
					return nil, err
				}

				conn.(*net.TCPConn).SetKeepAlive(true)
				return conn, nil
			},
			TLSClientConfig: config,
			DialTLS: func(network, addr string) (net.Conn, error) {
				conn, err := dialer.Dial("tcp", server)
				if err != nil {
					return nil, err
				}

				conn.(*net.TCPConn).SetKeepAlive(true)
				return tls.Client(conn, config), nil
			},
			DialTLSContext: func(ctx context.Context, network, addr string) (net.Conn, error) {
				conn, err := dialer.DialContext(ctx, "tcp", server)
				if err != nil {
					return nil, err
				}

				conn.(*net.TCPConn).SetKeepAlive(true)
				return tls.Client(conn, config), nil
			},
			ForceAttemptHTTP2: true,
		}

		return &DoHWireformat{
			BaseUrl: s,
			Timeout: time.Second * 3,
			Client: http.Client{
				Transport: transport,
				Timeout:   time.Second * 3,
			},
		}, nil
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
		return 0, fmt.Errorf("dial %v, error: %v", r.Addr, err)
	}
	defer conn.Close()

	_, err = conn.Write(b[2:2+n])
	if err != nil {
		return 0, fmt.Errorf("write to %v, error: %v", r.Addr, err)
	}

	err = conn.SetReadDeadline(time.Now().Add(r.Timeout))
	if err != nil {
		return 0, fmt.Errorf("set read deadline, error: %v", err)
	}

	n, err = conn.Read(b[2:])
	if err != nil {
		return 0, fmt.Errorf("read from %v, error: %v", r.Addr, err)
	}

	return n, nil
}

type TCPResolver struct {
	Addr    string
	Timeout time.Duration
}

func (r *TCPResolver) Resolve(b []byte, n int) (int, error) {
	conn, err := net.Dial("tcp", r.Addr)
	if err != nil {
		return 0, fmt.Errorf("dial %v, error: %v", r.Addr, err)
	}
	defer conn.Close()

	binary.BigEndian.PutUint16(b[:2], uint16(n))
	_, err = conn.Write(b[:2+n])
	if err != nil {
		return 0, fmt.Errorf("write to %v, error: %v", r.Addr, err)
	}

	err = conn.SetReadDeadline(time.Now().Add(r.Timeout))
	if err != nil {
		return 0, fmt.Errorf("set read deadline, error: %v", err)
	}

	_, err = io.ReadFull(conn, b[:2])
	if err != nil {
		return 0, fmt.Errorf("read lenfth from %v, error: %v", r.Addr, err)
	}

	n, err = io.ReadFull(conn, b[2:2+binary.BigEndian.Uint16(b[:2])])
	if err != nil {
		return 0, fmt.Errorf("read payload from %v, error: %v", r.Addr, err)
	}

	return n, nil
}

type TLSResolver struct {
	Conf    *tls.Config
	Addr    string
	Timeout time.Duration
}

func (r *TLSResolver) Resolve(b []byte, n int) (int, error) {
	conn, err := tls.Dial("tcp", r.Addr, r.Conf)
	if err != nil {
		return 0, fmt.Errorf("dial %v, error: %v", r.Addr, err)
	}
	defer conn.Close()

	binary.BigEndian.PutUint16(b[:2], uint16(n))
	_, err = conn.Write(b[:2+n])
	if err != nil {
		return 0, fmt.Errorf("write to %v, error: %v", r.Addr, err)
	}

	err = conn.SetReadDeadline(time.Now().Add(r.Timeout))
	if err != nil {
		return 0, fmt.Errorf("set read deadline, error: %v", err)
	}

	_, err = io.ReadFull(conn, b[:2])
	if err != nil {
		return 0, fmt.Errorf("read length from %v, error: %v", r.Addr, err)
	}

	n, err = io.ReadFull(conn, b[2:2+binary.BigEndian.Uint16(b[:2])])
	if err != nil {
		return 0, fmt.Errorf("read payload from %v, error: %v", r.Addr, err)
	}

	return n, nil
}

type DoHWireformat struct {
	BaseUrl string
	Timeout time.Duration
	http.Client
}

func (r *DoHWireformat) Resolve(b []byte, n int) (int, error) {
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

	n = 2
	for {
		nr, err := res.Body.Read(b[n:])
		n += nr
		if err != nil {
			if err == io.EOF {
				return n - 2, nil
			}
			return n - 2, err
		}
	}
}

func (r *DoHWireformat) Get(b []byte, n int) (int, error) {
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

	n = 2
	for {
		nr, err := res.Body.Read(b[n:])
		n += nr
		if err != nil {
			if err == io.EOF {
				return n - 2, nil
			}
			return n - 2, err
		}
	}
}
