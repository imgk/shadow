package shadowsocks

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
	"net/http"
	"reflect"
	"strconv"
	"time"
	"unsafe"

	"github.com/imgk/shadow/pkg/gonet"
)

// TLSDialer transfer shadowsocks data over tcp and tls with HTTP CONNECT tunnel
type TLSDialer struct {
	proxyIP   net.IP
	proxyPort int
	proxyAuth string
	tlsConfig *tls.Config
}

// NewTLSDialer replace original NewClient to support new protocol
func NewTLSDialer(server string, password string) (*TLSDialer, error) {
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

	proxyAddr, err := net.ResolveIPAddr("ip", host)
	if err != nil {
		return nil, errors.New("Failed to resolve proxy address")
	}
	sum := sha256.Sum224([]byte(password))
	proxyAuth := fmt.Sprintf("Basic %v", base64.StdEncoding.EncodeToString([]byte(hex.EncodeToString(sum[:]))))

	client := &TLSDialer{
		proxyIP:   proxyAddr.IP,
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
func (d *TLSDialer) Dial(network, addr string) (net.Conn, error) {
	proxyAddr := &net.TCPAddr{IP: d.proxyIP, Port: d.proxyPort}
	proxyConn, err := net.DialTCP("tcp", nil, proxyAddr)
	if err != nil {
		return nil, err
	}
	proxyConn.SetKeepAlive(true)

	conn := NewConn(proxyConn, d.proxyAuth, d.tlsConfig)
	return conn, nil
}

// ListenPacket gives a net.PacketConn
func (d *TLSDialer) ListenPacket(network, addr string) (net.PacketConn, error) {
	proxyAddr := &net.TCPAddr{IP: d.proxyIP, Port: d.proxyPort}
	proxyConn, err := net.DialTCP("tcp", nil, proxyAddr)
	if err != nil {
		return nil, err
	}
	proxyConn.SetKeepAlive(true)

	conn := NewPacketConn(proxyConn, d.proxyAuth, d.tlsConfig)
	return conn, nil
}

var (
	_ gonet.Conn     = (*Conn)(nil)
	_ net.Conn       = (*Conn)(nil)
	_ net.PacketConn = (*PacketConn)(nil)
)

// Conn supports net.Conn
type Conn struct {
	// Conn is ...
	net.Conn
	// Reader is ...
	Reader io.Reader
	// Writer is ...
	Writer io.Writer

	// local address
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

// PacketConn is to gives a new net.PacketConn
type PacketConn struct {
	// Conn is ...
	Conn
	// remote address
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

// CloseRead is gonet.CloseReader
func (c *Conn) CloseRead() error {
	if closer, ok := c.Conn.(gonet.CloseReader); ok {
		return closer.CloseRead()
	}
	c.Conn.SetReadDeadline(time.Now())
	return c.Conn.Close()
}

// CloseWrite is gonet.CloseWriter
func (c *Conn) CloseWrite() error {
	if closer, ok := c.Conn.(gonet.CloseWriter); ok {
		return closer.CloseWrite()
	}
	c.Conn.SetWriteDeadline(time.Now())
	return c.Conn.Close()
}

// Equal is ...
func Equal(b []byte, s string) bool {
	type StringHeader struct {
		Data uintptr
		Len  int
	}

	bb := (*reflect.SliceHeader)(unsafe.Pointer(&b))
	ss := *(*string)(unsafe.Pointer(&StringHeader{
		Data: bb.Data,
		Len:  bb.Len,
	}))
	return s == ss
}

// Read is io.Reader
func (c *Conn) Read(b []byte) (int, error) {
	const Response = "HTTP/1.1 200 Connection Established\r\n\r\n"
	if c.Reader == nil {
		bb := make([]byte, len(Response))
		if _, err := io.ReadFull(c.Conn, bb); err != nil {
			return 0, err
		}
		if Equal(bb, Response) {
			return 0, errors.New("response error")
		}
		c.Reader = c.Conn
	}
	return c.Reader.Read(b)
}

// Write is io.Writer
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

// Read is net.Conn.Read
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

// ReadFrom is net.PacketConn.ReadFrom
func (c *PacketConn) ReadFrom(b []byte) (int, net.Addr, error) {
	n, err := c.Read(b)
	return n, c.nAddr, err
}

// Write is net.Conn.Write
func (c *PacketConn) Write(b []byte) (int, error) {
	bb := make([]byte, 2)
	bb[0] = byte(len(b) >> 8)
	bb[1] = byte(len(b))
	if _, err := c.Conn.Write(bb); err != nil {
		return 0, err
	}
	return c.Conn.Write(b)
}

// WriteTo is net.PacketConn.WriteTo
func (c *PacketConn) WriteTo(b []byte, addr net.Addr) (int, error) {
	return c.Write(b)
}
