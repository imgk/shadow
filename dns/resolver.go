package dns

import (
	"bytes"
	"crypto/tls"
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
		return nil, fmt.Errorf("failed to parse url %v error: %v", s, err)
	}

	switch u.Scheme {
	case "udp":
		_, err := net.ResolveUDPAddr("udp", net.JoinHostPort(u.Host, "53"))
		if err != nil {
			return nil, err
		}

		return &UDPResolver{Addr: net.JoinHostPort(u.Host, "53"), Timeout: time.Second * 3}, nil
	case "tcp":
		_, err := net.ResolveTCPAddr("tcp", net.JoinHostPort(u.Host, "53"))
		if err != nil {
			return nil, err
		}

		return &TCPResolver{Addr: net.JoinHostPort(u.Host, "53"), Timeout: time.Second * 3}, nil
	case "tls":
		_, err := net.ResolveTCPAddr("tcp", net.JoinHostPort(u.Host, "853"))
		if err != nil {
			return nil, err
		}

		return &TLSResolver{Conf: &tls.Config{ServerName: u.Host}, Addr: net.JoinHostPort(u.Host, "853"), Timeout: time.Second * 3}, nil
	case "https":
		_, err := net.ResolveTCPAddr("tcp", net.JoinHostPort(u.Host, "443"))
		if err != nil {
			return nil, err
		}

		return &DoHWireformat{BaseUrl: s, Timeout: time.Second * 3, Client: http.Client{Timeout: time.Second * 3}}, nil
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
		return 0, fmt.Errorf("failed to dial %v, error: %v", r.Addr, err)
	}
	defer conn.Close()

	_, err = conn.Write(b[2 : 2+n])
	if err != nil {
		return 0, fmt.Errorf("failed to write to %v, error: %v", r.Addr, err)
	}

	err = conn.SetReadDeadline(time.Now().Add(r.Timeout))
	if err != nil {
		return 0, fmt.Errorf("failed to set read deadline, error: %v", err)
	}

	n, err = conn.Read(b[2:])
	if err != nil {
		return 0, fmt.Errorf("failed to read from %v, error: %v", r.Addr, err)
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
		return 0, fmt.Errorf("failed to dial %v, error: %v", r.Addr, err)
	}
	defer conn.Close()

	binary.BigEndian.PutUint16(b[:2], uint16(n))
	_, err = conn.Write(b[:2+n])
	if err != nil {
		return 0, fmt.Errorf("failed to write to %v, error: %v", r.Addr, err)
	}

	err = conn.SetReadDeadline(time.Now().Add(r.Timeout))
	if err != nil {
		return 0, fmt.Errorf("failed to set read deadline, error: %v", err)
	}

	_, err = io.ReadFull(conn, b[:2])
	if err != nil {
		return 0, fmt.Errorf("failed to read lenfth from %v, error: %v", r.Addr, err)
	}

	n, err = io.ReadFull(conn, b[2:2+binary.BigEndian.Uint16(b[:2])])
	if err != nil {
		return 0, fmt.Errorf("failed to read payload from %v, error: %v", r.Addr, err)
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
		return 0, fmt.Errorf("failed to dial %v, error: %v", r.Addr, err)
	}
	defer conn.Close()

	binary.BigEndian.PutUint16(b[:2], uint16(n))
	_, err = conn.Write(b[:2+n])
	if err != nil {
		return 0, fmt.Errorf("failed to write to %v, error: %v", r.Addr, err)
	}

	err = conn.SetReadDeadline(time.Now().Add(r.Timeout))
	if err != nil {
		return 0, fmt.Errorf("failed to set read deadline, error: %v", err)
	}

	_, err = io.ReadFull(conn, b[:2])
	if err != nil {
		return 0, fmt.Errorf("failed to read length from %v, error: %v", r.Addr, err)
	}

	n, err = io.ReadFull(conn, b[2:2+binary.BigEndian.Uint16(b[:2])])
	if err != nil {
		return 0, fmt.Errorf("failed to read payload from %v, error: %v", r.Addr, err)
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
