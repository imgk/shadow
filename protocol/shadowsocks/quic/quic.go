package quic

import (
	"crypto/sha256"
	"crypto/tls"
	"encoding/base64"
	"encoding/hex"
	"errors"
	"fmt"
	"io"
	"math"
	"net"
	"strconv"

	"github.com/lucas-clemente/quic-go"
)

type Dialer struct {
	sess      quic.Session
	proxyAuth string
}

func NewDialer(server, password string) (*Dialer, error) {
	host, portString, err := net.SplitHostPort(server)
	if err != nil {
		return nil, err
	}
	port, err := strconv.Atoi(portString)
	if err != nil {
		return nil, err
	}
	if port > math.MaxUint16 || port != 443 {
		return nil, errors.New("port number error")
	}

	_, err = net.ResolveIPAddr("ip", host)
	if err != nil {
		return nil, errors.New("Failed to resolve proxy address")
	}
	sum := sha256.Sum224([]byte(password))
	proxyAuth := fmt.Sprintf("Basic %v", base64.StdEncoding.EncodeToString([]byte(hex.EncodeToString(sum[:]))))

	tlsConfig := &tls.Config{
		ServerName:         host,
		ClientSessionCache: tls.NewLRUClientSessionCache(32),
	}
	config := &quic.Config{}
	sess, err := quic.DialAddr(server, tlsConfig, config)
	if err != nil {
		return nil, err
	}
	client := &Dialer{
		sess:      sess,
		proxyAuth: proxyAuth,
	}
	return client, nil
}

func (d *Dialer) Dial(network, addr string) (net.Conn, error) {
	stream, err := d.sess.OpenStream()
	if err != nil {
		return nil, err
	}
	conn := NewConn(d.sess, stream, d.proxyAuth)
	return conn, nil
}

func (d *Dialer) ListenPacket(network, addr string) (net.PacketConn, error) {
	stream, err := d.sess.OpenStream()
	if err != nil {
		return nil, err
	}
	conn := NewPacketConn(d.sess, stream, d.proxyAuth)
	return conn, nil
}

var (
	_ DuplexConn     = (*Conn)(nil)
	_ net.Conn       = (*Conn)(nil)
	_ net.PacketConn = (*PacketConn)(nil)
)

type CloseReader interface {
	CloseRead() error
}

type CloseWriter interface {
	CloseWrite() error
}

// DuplexConn supports CloseRead and CloseWrite
type DuplexConn interface {
	net.Conn
	CloseReader
	CloseWriter
}

type Conn struct {
	quic.Session
	quic.Stream
	Reader io.Reader
	Writer io.Writer

	nAddr net.Addr

	proxyAuth string
	proxyHost string
}

func NewConn(sess quic.Session, stream quic.Stream, proxyAuth string) net.Conn {
	nAddr, _ := net.ResolveUDPAddr("tcp", sess.LocalAddr().String())
	conn := &Conn{
		Session:   sess,
		Stream:    stream,
		nAddr:     nAddr,
		proxyAuth: proxyAuth,
		proxyHost: "tcp.imgk.cc",
	}
	return conn
}

type PacketConn struct {
	Conn
	nAddr net.Addr
}

func NewPacketConn(sess quic.Session, stream quic.Stream, proxyAuth string) net.PacketConn {
	nAddr, _ := net.ResolveUDPAddr("udp", sess.LocalAddr().String())
	rAddr, _ := net.ResolveUDPAddr("udp", sess.RemoteAddr().String())
	conn := &PacketConn{
		Conn: Conn{
			Session:   sess,
			Stream:    stream,
			nAddr:     nAddr,
			proxyAuth: proxyAuth,
			proxyHost: "udp.imgk.cc",
		},
		nAddr: rAddr,
	}
	return conn
}

func (c *Conn) LocalAddr() net.Addr {
	return c.nAddr
}

func (c *Conn) CloseRead() error {
	return nil
}

func (c *Conn) CloseWrite() error {
	return nil
}

var response = []byte("HTTP/1.1 200 Connection Established\r\n\r\n")

func (c *Conn) Write(b []byte) (int, error) {
	if c.Writer == nil {
	}
	return c.Writer.Write(b)
}

func (c *Conn) Read(b []byte) (int, error) {
	if c.Reader == nil {
	}
	return c.Reader.Read(b)
}

func (c *PacketConn) Read(b []byte) (int, error) {
	if _, err := io.ReadFull(io.Reader(&c.Conn), b[:2]); err != nil {
		return 0, err
	}
	n := int(b[0])<<8 | int(b[1])
	if _, err := io.ReadFull(io.Reader(&c.Conn), b[:n]); err != nil {
		return 0, err
	}
	return n, nil
}

func (c *PacketConn) ReadFrom(b []byte) (int, net.Addr, error) {
	n, err := c.Read(b)
	return n, c.nAddr, err
}

func (c *PacketConn) Write(b []byte) (int, error) {
	bb := make([]byte, 2)
	bb[0] = byte(len(b) >> 8)
	bb[1] = byte(len(b))
	if _, err := c.Conn.Write(bb); err != nil {
		return 0, err
	}
	return c.Conn.Write(b)
}

func (c *PacketConn) WriteTo(b []byte, addr net.Addr) (int, error) {
	return c.Write(b)
}
