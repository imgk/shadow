package main

import (
	"crypto/tls"
	"encoding/binary"
	"fmt"
	"io"
	"net"
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
		addr, err := net.ResolveUDPAddr("udp", net.JoinHostPort(u.Host, "53"))
		if err != nil {
			return nil, err
		}

		return &UDPResolver{Addr: addr, Timeout: time.Second * 3}, nil
	case "tcp":
		addr, err := net.ResolveTCPAddr("tcp", net.JoinHostPort(u.Host, "53"))
		if err != nil {
			return nil, err
		}

		return &TCPResolver{Addr: addr, Timeout: time.Second * 3}, nil
	case "tls":
		addr, err := net.ResolveTCPAddr("tcp", net.JoinHostPort(u.Host, "853"))
		if err != nil {
			return nil, err
		}

		return &TLSResolver{Addr: addr, Timeout: time.Second * 3, Conf: &tls.Config{ServerName: u.Host}}, nil
	default:
		return nil, fmt.Errorf("not a valid dns protocol")
	}
}

type UDPResolver struct {
	Addr    *net.UDPAddr
	Timeout time.Duration
}

func (r *UDPResolver) Resolve(b []byte, n int) (int, error) {
	var conn net.Conn

	conn, err := net.DialUDP("udp", nil, r.Addr)
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
	Addr    *net.TCPAddr
	Timeout time.Duration
}

func (r *TCPResolver) Resolve(b []byte, n int) (int, error) {
	var conn net.Conn

	conn, err := net.DialTCP("tcp", nil, r.Addr)
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
	Addr    *net.TCPAddr
	Timeout time.Duration
}

func (r *TLSResolver) Resolve(b []byte, n int) (int, error) {
	var conn net.Conn

	conn, err := net.DialTCP("tcp", nil, r.Addr)
	if err != nil {
		return 0, fmt.Errorf("failed to dial %v, error: %v", r.Addr, err)
	}
	conn = tls.Client(conn, r.Conf)
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
