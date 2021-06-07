package http2

import (
	"crypto/sha256"
	"crypto/tls"
	"encoding/base64"
	"encoding/hex"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/url"
	"time"

	"github.com/lucas-clemente/quic-go"
	"github.com/lucas-clemente/quic-go/http3"
	"golang.org/x/net/http2"

	"github.com/imgk/shadow/pkg/gonet"
	"github.com/imgk/shadow/pkg/pool"
	"github.com/imgk/shadow/pkg/socks"
)

// HeaderLen is ...
const HeaderLen = 56

// NetDialer is ...
type NetDialer struct {
	// Dialer is ...
	Dialer net.Dialer
	// Addr is ...
	Addr string
}

// DialTLS is ...
func (d *NetDialer) DialTLS(network, addr string, cfg *tls.Config) (conn net.Conn, err error) {
	conn, err = net.Dial(network, d.Addr)
	if err != nil {
		return
	}
	conn = tls.Client(conn, cfg)
	return
}

// QUICDialer is ...
type QUICDialer struct {
	// Addr is ...
	Addr string
}

// Dial is ...
func (d *QUICDialer) Dial(network, addr string, tlsCfg *tls.Config, cfg *quic.Config) (quic.EarlySession, error) {
	return quic.DialAddrEarly(d.Addr, tlsCfg, cfg)
}

// Handler is ...
type Handler struct {
	// NewRequest is ...
	NewRequest func(string, io.ReadCloser, string) *http.Request
	// Client is ...
	http.Client

	proxyAuth string
	timeout   time.Duration
}

// NewHandler is ...
func NewHandler(server, path, password, domain string, timeout time.Duration) (*Handler, error) {
	auth := func(password string) string {
		buff := [HeaderLen]byte{}
		hash := sha256.Sum224([]byte(password))
		hex.Encode(buff[:HeaderLen], hash[:])
		return fmt.Sprintf("Basic %v", base64.StdEncoding.EncodeToString(buff[:]))
	}(password)

	dialer := NetDialer{Addr: server}
	handler := &Handler{
		NewRequest: func(addr string, body io.ReadCloser, auth string) *http.Request {
			r := &http.Request{
				Method: http.MethodConnect,
				Host:   addr,
				Body:   body,
				URL: &url.URL{
					Scheme: "https",
					Host:   addr,
				},
				Proto:      "HTTP/2",
				ProtoMajor: 2,
				ProtoMinor: 0,
				Header:     make(http.Header),
			}
			r.Header.Set("Accept-Encoding", "identity")
			r.Header.Add("Proxy-Authorization", auth)
			return r
		},
		Client: http.Client{
			Transport: &http2.Transport{
				DialTLS: dialer.DialTLS,
				TLSClientConfig: &tls.Config{
					ServerName:         domain,
					ClientSessionCache: tls.NewLRUClientSessionCache(32),
				},
			},
		},
		proxyAuth: auth,
		timeout:   timeout,
	}
	return handler, nil
}

// NewQUICHandler is ...
func NewQUICHandler(server, path, password, domain string, timeout time.Duration) (*Handler, error) {
	auth := func(password string) string {
		buff := [HeaderLen]byte{}
		hash := sha256.Sum224([]byte(password))
		hex.Encode(buff[:HeaderLen], hash[:])
		return fmt.Sprintf("Basic %v", base64.StdEncoding.EncodeToString(buff[:]))
	}(password)

	dialer := QUICDialer{Addr: server}
	handler := &Handler{
		NewRequest: func(addr string, body io.ReadCloser, auth string) *http.Request {
			r := &http.Request{
				Method: http.MethodConnect,
				Host:   addr,
				Body:   body,
				URL: &url.URL{
					Scheme: "https",
					Host:   addr,
				},
				Proto:      "HTTP/3",
				ProtoMajor: 3,
				ProtoMinor: 0,
				Header:     make(http.Header),
			}
			r.Header.Set("Accept-Encoding", "identity")
			r.Header.Add("Proxy-Authorization", auth)
			return r
		},
		Client: http.Client{
			Transport: &http3.RoundTripper{
				Dial: dialer.Dial,
				TLSClientConfig: &tls.Config{
					ServerName:         domain,
					ClientSessionCache: tls.NewLRUClientSessionCache(32),
				},
				QuicConfig: &quic.Config{KeepAlive: true},
			},
		},
		proxyAuth: auth,
		timeout:   timeout,
	}
	return handler, nil
}

// Close is ...
func (*Handler) Close() error {
	return nil
}

// Handle is ...
func (h *Handler) Handle(conn gonet.Conn, tgt net.Addr) error {
	defer conn.Close()

	rc := NewReader(conn, tgt)
	req := h.NewRequest("tcp.imgk.cc", rc, h.proxyAuth)

	r, err := h.Client.Do(req)
	if err != nil {
		return fmt.Errorf("do request error: %w", err)
	}
	defer r.Body.Close()
	if r.StatusCode != http.StatusOK {
		return fmt.Errorf("response status code error: %v", r.StatusCode)
	}

	if _, err := gonet.Copy(io.Writer(conn), r.Body); err != nil {
		conn.CloseWrite()
		rc.Wait()
		return fmt.Errorf("WriteTo error: %w", err)
	}
	conn.CloseWrite()
	rc.Wait()
	return nil
}

// HandlePacket is ...
func (h *Handler) HandlePacket(conn gonet.PacketConn) error {
	defer conn.Close()

	rc := NewPacketReader(conn, h.timeout)
	req := h.NewRequest("udp.imgk.cc", rc, h.proxyAuth)

	r, err := h.Client.Do(req)
	if err != nil {
		return fmt.Errorf("do request error: %w", err)
	}
	defer r.Body.Close()
	if r.StatusCode != http.StatusOK {
		return fmt.Errorf("response status code error: %v", r.StatusCode)
	}

	err = func(rc io.ReadCloser, conn gonet.PacketConn) (err error) {
		const MaxBufferSize = 16 << 10

		sc, b := pool.Pool.Get(MaxBufferSize)
		defer pool.Pool.Put(sc)

		for {
			raddr, er := socks.ReadAddrBuffer(rc, b)
			if er != nil {
				err = er
				break
			}

			n := len(raddr.Addr)
			if _, er := io.ReadFull(rc, b[n:n+4]); er != nil {
				err = er
				break
			}

			n += (int(b[n])<<8 | int(b[n+1]))
			if _, er := io.ReadFull(rc, b[len(raddr.Addr):n]); er != nil {
				err = er
				break
			}

			if _, ew := conn.WriteFrom(b[len(raddr.Addr):n], raddr); ew != nil {
				err = ew
				break
			}
		}
		return
	}(r.Body, conn)

	if errors.Is(err, io.EOF) {
		return nil
	}
	return err
}

// WriteAddr is ...
func WriteAddr(b []byte, cmd byte, tgt net.Addr) (int, error) {
	if len(b) < 1+socks.MaxAddrLen+2 {
		return 0, io.ErrShortBuffer
	}

	buff := b[:1+socks.MaxAddrLen+2]
	buff[0] = cmd

	if addr, ok := tgt.(*socks.Addr); ok {
		buff = append(buff[:1], addr.Addr...)
	} else {
		addr, err := socks.ResolveAddrBuffer(tgt, buff[1:])
		if err != nil {
			return 0, err
		}
		buff = buff[:1+len(addr.Addr)]
	}

	buff = append(buff, 0x0d, 0x0a)
	return len(buff), nil
}

// Reader is ...
type Reader struct {
	// Conn is ...
	Conn gonet.Conn
	// Reader is ...
	Reader io.Reader

	tgt    net.Addr
	closed chan struct{}
}

// NewReader is ...
func NewReader(conn gonet.Conn, tgt net.Addr) *Reader {
	r := &Reader{
		Conn:   conn,
		Reader: nil,
		tgt:    tgt,
		closed: make(chan struct{}),
	}
	return r
}

// Read is ...
func (r *Reader) Read(b []byte) (int, error) {
	if r.Reader == nil {
		r.Reader = r.Conn
		n, err := WriteAddr(b, socks.CmdConnect, r.tgt)
		if err != nil {
			return n, io.EOF
		}
		return n, nil
	}
	n, err := r.Reader.Read(b)
	if err != nil {
		return n, io.EOF
	}
	return n, nil
}

// Close is ...
func (r *Reader) Close() error {
	select {
	case <-r.closed:
		return nil
	default:
		close(r.closed)
	}
	return nil
}

// Wait is ...
func (r *Reader) Wait() {
	<-r.closed
}

// PacketReader is ...
type PacketReader struct {
	// Closer is ...
	io.Closer
	// Reader is ...
	Reader gonet.PacketConn

	timeout time.Duration
}

// NewPacketReader is ...
func NewPacketReader(conn gonet.PacketConn, timeout time.Duration) *PacketReader {
	r := &PacketReader{
		Closer:  nil,
		Reader:  conn,
		timeout: timeout,
	}
	return r
}

// Read is ...
func (r *PacketReader) Read(b []byte) (int, error) {
	if r.Closer == nil {
		r.Closer = r.Reader
		return WriteAddr(b, socks.CmdAssociate, r.Reader.LocalAddr())
	}
	bb := b[socks.MaxAddrLen+4:]
	r.Reader.SetReadDeadline(time.Now().Add(r.timeout))
	n, tgt, err := r.Reader.ReadTo(bb)
	if err != nil {
		return 0, io.EOF
	}
	addr, err := socks.ResolveAddrBuffer(tgt, b[0:])
	if err != nil {
		return 0, io.EOF
	}
	b = append(b[:len(addr.Addr)], byte(n>>8), byte(n), 0x0d, 0x0a)
	b = append(b, bb[:n]...)
	return len(b), nil
}

// Close is ...
func (r *PacketReader) Close() error {
	return nil
}
