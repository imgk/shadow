package tls

import (
	"bytes"
	"crypto/sha256"
	"crypto/tls"
	"encoding/base64"
	"encoding/hex"
	"errors"
	"fmt"
	"io"
	"math"
	"net"
	"net/http"
	"strconv"
)

// transfer shadowsocks data over tcp and tls with HTTP CONNECT tunnel
type Dialer struct {
	proxyIP   net.IP
	proxyPort int
	proxyAuth string
	tlsConfig *tls.Config
}

// NewClient replace original NewClient to support new protocol
func NewDialer(server string, password string) (*Dialer, error) {
	host, portString, err := net.SplitHostPort(server)
	if err != nil {
		return nil, err
	}
	port, err := strconv.Atoi(portString)
	if err != nil {
		return nil, err
	}
	if port > math.MaxUint16 || (port != 80 && port != 443) {
		return nil, errors.New("port number error")
	}

	proxyIP, err := net.ResolveIPAddr("ip", host)
	if err != nil {
		return nil, errors.New("Failed to resolve proxy address")
	}
	sum := sha256.Sum224([]byte(password))
	proxyAuth := fmt.Sprintf("Basic %v", base64.StdEncoding.EncodeToString([]byte(hex.EncodeToString(sum[:]))))

	client := &Dialer{
		proxyIP:   proxyIP.IP,
		proxyPort: port,
		proxyAuth: proxyAuth,
	}
	if port == 443 {
		client.tlsConfig = &tls.Config{
			ServerName:         host,
			ClientSessionCache: tls.NewLRUClientSessionCache(32),
		}
	}
	return client, nil
}

// Dial gives a net.Conn
func (c *Dialer) Dial(network, addr string) (net.Conn, error) {
	proxyAddr := &net.TCPAddr{IP: c.proxyIP, Port: c.proxyPort}
	proxyConn, err := net.DialTCP("tcp", nil, proxyAddr)
	if err != nil {
		return nil, err
	}
	proxyConn.SetKeepAlive(true)

	conn := NewConn(proxyConn, c.proxyAuth, c.tlsConfig)
	return conn, nil
}

// ListenPacket gives a net.PacketConn
func (c *Dialer) ListenPacket(network, addr string) (net.PacketConn, error) {
	proxyAddr := &net.TCPAddr{IP: c.proxyIP, Port: c.proxyPort}
	proxyConn, err := net.DialTCP("tcp", nil, proxyAddr)
	if err != nil {
		return nil, err
	}
	proxyConn.SetKeepAlive(true)

	conn := NewPacketConn(proxyConn, c.proxyAuth, c.tlsConfig)
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

// Conn supports net.Conn
type Conn struct {
	net.Conn
	Reader io.Reader
	Writer io.Writer

	nAddr net.Addr

	proxyAuth string
	proxyHost string
}

// NewConn gives a new net.Conn
func NewConn(nc *net.TCPConn, proxyAuth string, cfg *tls.Config) net.Conn {
	nAddr := nc.LocalAddr().(*net.TCPAddr)
	conn := &Conn{
		nAddr:     &net.TCPAddr{IP: nAddr.IP, Port: nAddr.Port},
		proxyAuth: proxyAuth,
		proxyHost: "tcp.imgk.cc",
	}
	if cfg == nil {
		conn.Conn = nc
	} else {
		conn.Conn = tls.Client(nc, cfg)
	}
	return conn
}

// NewConn gives a new net.PacketConn
type PacketConn struct {
	Conn
	nAddr net.Addr
}

// NewPacketConn gives a new net.PacketConn
func NewPacketConn(nc *net.TCPConn, proxyAuth string, cfg *tls.Config) net.PacketConn {
	nAddr := nc.LocalAddr().(*net.TCPAddr)
	rAddr := nc.RemoteAddr().(*net.TCPAddr)
	conn := &PacketConn{
		Conn: Conn{
			nAddr:     &net.UDPAddr{IP: nAddr.IP, Port: nAddr.Port},
			proxyAuth: proxyAuth,
			proxyHost: "udp.imgk.cc",
		},
		nAddr: &net.UDPAddr{IP: rAddr.IP, Port: rAddr.Port},
	}
	if cfg == nil {
		conn.Conn.Conn = nc
	} else {
		conn.Conn.Conn = tls.Client(nc, cfg)
	}
	return conn
}

// LocalAddr net.Conn.LocalAddr and net.PacketConn.LocalAddr
func (c *Conn) LocalAddr() net.Addr {
	return c.nAddr
}

// CloseRead CloseReader
func (c *Conn) CloseRead() error {
	if closer, ok := c.Conn.(CloseReader); ok {
		return closer.CloseRead()
	}
	return c.Conn.Close()
}

// CloseWrite CloseWriter
func (c *Conn) CloseWrite() error {
	if closer, ok := c.Conn.(CloseWriter); ok {
		return closer.CloseWrite()
	}
	return c.Conn.Close()
}

var response = []byte("HTTP/1.1 200 Connection Established\r\n\r\n")

// Read io.Reader
func (c *Conn) Read(b []byte) (int, error) {
	if c.Reader == nil {
		// "HTTP/1.1 200 Connection Established\r\n\r\n"
		bb := make([]byte, len(response))
		if _, err := io.ReadFull(c.Conn, bb); err != nil {
			return 0, err
		}
		if !bytes.Equal(bb, response) {
			return 0, errors.New("response error")
		}
		c.Reader = c.Conn
	}
	return c.Reader.Read(b)
}

// Write io.Writer
func (c *Conn) Write(b []byte) (int, error) {
	if c.Writer == nil {
		if conn, ok := c.Conn.(*tls.Conn); ok {
			if err := conn.Handshake(); err != nil {
				return 0, err
			}
		}
		r, err := http.NewRequest(http.MethodConnect, "", nil)
		if err != nil {
			return 0, err
		}
		r.Host = c.proxyHost
		r.Header.Add("Proxy-Authorization", c.proxyAuth)
		if err := r.Write(c.Conn); err != nil {
			return 0, err
		}
		c.Writer = c.Conn
	}
	return c.Writer.Write(b)
}

// Read net.Conn.Read
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

// ReadFrom net.PacketConn.ReadFrom
func (c *PacketConn) ReadFrom(b []byte) (int, net.Addr, error) {
	n, err := c.Read(b)
	return n, c.nAddr, err
}

// Write net.Conn.Write
func (c *PacketConn) Write(b []byte) (int, error) {
	bb := make([]byte, 2)
	bb[0] = byte(len(b) >> 8)
	bb[1] = byte(len(b))
	if _, err := c.Conn.Write(bb); err != nil {
		return 0, err
	}
	return c.Conn.Write(b)
}

// WriteTo net.PacketConn.WriteTo
func (c *PacketConn) WriteTo(b []byte, addr net.Addr) (int, error) {
	return c.Write(b)
}
