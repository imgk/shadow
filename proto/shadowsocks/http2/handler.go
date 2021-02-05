package http2

import (
	"crypto/cipher"
	"crypto/rand"
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

	"golang.org/x/net/http2"

	"github.com/lucas-clemente/quic-go"
	"github.com/lucas-clemente/quic-go/http3"

	"github.com/imgk/shadow/pkg/gonet"
	"github.com/imgk/shadow/pkg/pool"
	"github.com/imgk/shadow/pkg/socks"
	"github.com/imgk/shadow/proto/shadowsocks/core"
)

var zerononce = [128]byte{}

// Handler is ...
type Handler struct {
	// NewReqeust is ...
	NewRequest func(string, io.ReadCloser, string) *http.Request

	// Cipher is ...
	Cipher *core.Cipher
	// Client is ...
	Client http.Client

	proxyAuth string
	timeout   time.Duration
}

// MewHandler is ...
func NewHandler(s string, timeout time.Duration) (*Handler, error) {
	server, method, password, err := ParseURL(s)
	if err != nil {
		return nil, err
	}

	proxyIP, err := net.ResolveUDPAddr("udp", server)
	if err != nil {
		return nil, err
	}

	cipher, err := core.NewCipher(method, password)
	if err != nil {
		return nil, err
	}

	host, portString, err := net.SplitHostPort(server)
	if err != nil {
		return nil, err
	}
	server = net.JoinHostPort(proxyIP.IP.String(), portString)

	sum := sha256.Sum224([]byte(password))
	proxyAuth := fmt.Sprintf("Basic %v", base64.StdEncoding.EncodeToString([]byte(hex.EncodeToString(sum[:]))))

	return &Handler{
		NewRequest: func(addr string, body io.ReadCloser, auth string) (r *http.Request) {
			r = &http.Request{
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
			return
		},
		Cipher: cipher,
		Client: http.Client{
			Transport: &http2.Transport{
				DialTLS: func(network, addr string, cfg *tls.Config) (conn net.Conn, err error) {
					conn, err = net.Dial("tcp", server)
					if err != nil {
						return
					}
					conn = tls.Client(conn, cfg)
					return
				},
				TLSClientConfig: &tls.Config{
					ServerName:         host,
					ClientSessionCache: tls.NewLRUClientSessionCache(32),
				},
			},
		},
		proxyAuth: proxyAuth,
		timeout:   timeout,
	}, nil
}

// NewQUCIHandler is ...
func NewQUICHandler(s string, timeout time.Duration) (*Handler, error) {
	server, method, password, err := ParseURL(s)
	if err != nil {
		return nil, err
	}

	proxyIP, err := net.ResolveUDPAddr("udp", server)
	if err != nil {
		return nil, err
	}

	cipher, err := core.NewCipher(method, password)
	if err != nil {
		return nil, err
	}

	host, portString, err := net.SplitHostPort(server)
	if err != nil {
		return nil, err
	}
	server = net.JoinHostPort(proxyIP.IP.String(), portString)

	sum := sha256.Sum224([]byte(password))
	proxyAuth := fmt.Sprintf("Basic %v", base64.StdEncoding.EncodeToString([]byte(hex.EncodeToString(sum[:]))))

	return &Handler{
		NewRequest: func(addr string, body io.ReadCloser, auth string) (r *http.Request) {
			r = &http.Request{
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
			return
		},
		Cipher: cipher,
		Client: http.Client{
			Transport: &http3.RoundTripper{
				Dial: func(network, addr string, tlsCfg *tls.Config, cfg *quic.Config) (quic.EarlySession, error) {
					return quic.DialAddrEarly(server, tlsCfg, cfg)
				},
				TLSClientConfig: &tls.Config{
					ServerName:         host,
					ClientSessionCache: tls.NewLRUClientSessionCache(32),
				},
				QuicConfig: &quic.Config{KeepAlive: true},
			},
		},
		proxyAuth: proxyAuth,
		timeout:   timeout,
	}, nil
}

// Close is ...
func (h *Handler) Close() error {
	return nil
}

// Handle is ...
func (h *Handler) Handle(conn net.Conn, tgt net.Addr) error {
	defer conn.Close()

	req := h.NewRequest("tcp.imgk.cc", NewReader(h.Cipher, conn, tgt), h.proxyAuth)

	r, err := h.Client.Do(req)
	if err != nil {
		return fmt.Errorf("do request error: %w", err)
	}
	if r.StatusCode != http.StatusOK {
		return fmt.Errorf("response status code error: %v", r.StatusCode)
	}
	defer r.Body.Close()

	if _, err := core.NewReader(r.Body, h.Cipher).WriteTo(io.Writer(conn)); err != nil {
		return fmt.Errorf("WriteTo error: %w", err)
	}
	return nil
}

// HandlePacket is ...
func (h *Handler) HandlePacket(conn gonet.PacketConn) error {
	defer conn.Close()

	req := h.NewRequest("udp.imgk.cc", NewPacketReader(h.Cipher, conn, h.timeout), h.proxyAuth)

	r, err := h.Client.Do(req)
	if err != nil {
		return fmt.Errorf("do request error: %v", err)
	}
	if r.StatusCode != http.StatusOK {
		return fmt.Errorf("response status code error: %v", r.StatusCode)
	}
	defer r.Body.Close()

	err = func(r io.Reader) error {
		const MaxBufferSize = 16 << 10
		sc, b := pool.Pool.Get(MaxBufferSize)
		defer pool.Pool.Put(sc)

		for {
			if _, err := io.ReadFull(r, b[:2]); err != nil {
				if errors.Is(err, io.EOF) {
					return nil
				}
				return err
			}

			n := int(b[0])<<8 | int(b[1])

			if _, err := io.ReadFull(r, b[:n]); err != nil {
				return fmt.Errorf("read packet error: %v", err)
			}

			bb, err := func(pkt []byte, cipher *core.Cipher) ([]byte, error) {
				saltSize := cipher.SaltSize
				if len(pkt) < saltSize {
					return nil, core.ErrShortPacket
				}

				salt := pkt[:saltSize]
				aead, err := cipher.NewAEAD(salt)
				if err != nil {
					return nil, err
				}

				if len(pkt) < saltSize+aead.Overhead() {
					return nil, core.ErrShortPacket
				}

				return aead.Open(pkt[saltSize:saltSize], zerononce[:aead.NonceSize()], pkt[saltSize:], nil)
			}(b[:n], h.Cipher)
			if err != nil {
				return fmt.Errorf("unpack error: %v", err)
			}

			raddr, err := socks.ParseAddr(bb)
			if err != nil {
				return fmt.Errorf("parse socks.Addr error: %v", err)
			}

			if _, err := conn.WriteFrom(bb[len(raddr.Addr):], raddr); err != nil {
				if errors.Is(err, io.EOF) {
					return nil
				}
				return err
			}
		}
	}(r.Body)

	return err
}

func increment(b []byte) {
	for i := range b {
		b[i]++
		if b[i] != 0 {
			return
		}
	}
}

// Reader is ...
type Reader struct {
	// AEAD is ...
	cipher.AEAD

	// Cipher is ...
	Cipher *core.Cipher
	// Reader is ...
	Reader io.Reader

	tgt   net.Addr
	nonce []byte
}

// NewReader is ...
func NewReader(cipher *core.Cipher, rc io.ReadCloser, tgt net.Addr) *Reader {
	r := &Reader{
		Cipher: cipher,
		Reader: rc,
		tgt:    tgt,
	}
	return r
}

// Close is ...
func (r *Reader) Close() error {
	return nil
}

// Read is ...
func (r *Reader) Read(b []byte) (int, error) {
	if r.AEAD == nil {
		return r.init(b)
	}

	overhead := r.AEAD.Overhead()
	if len(b) < 2+overhead+overhead {
		return 0, io.ErrShortBuffer
	}
	if n := 2 + overhead + core.MaxPacketSize + overhead; len(b) > n {
		b = b[:n]
	}

	buf := b[2+overhead : len(b)-overhead]
	n, err := r.Reader.Read(buf)
	if err != nil {
		return 0, err
	}

	b[0] = byte(n >> 8)
	b[1] = byte(n)

	r.AEAD.Seal(b[:0], r.nonce, b[:2], nil)
	increment(r.nonce)

	r.AEAD.Seal(buf[:0], r.nonce, buf[:n], nil)
	increment(r.nonce)

	return 2 + overhead + n + overhead, nil
}

func (r *Reader) init(b []byte) (int, error) {
	saltSize := r.Cipher.SaltSize
	if len(b) < saltSize {
		return 0, io.ErrShortBuffer
	}

	salt := b[:saltSize]
	_, err := rand.Read(salt)
	if err != nil {
		return 0, err
	}

	r.AEAD, err = r.Cipher.NewAEAD(salt)
	if err != nil {
		return 0, err
	}
	r.nonce = make([]byte, r.AEAD.NonceSize())

	overhead := r.AEAD.Overhead()
	if len(b) < saltSize+2+overhead+socks.MaxAddrLen+overhead {
		return 0, io.ErrShortBuffer
	}

	b = b[saltSize:]
	buf := b[2+overhead:]

	n, err := func(b []byte, tgt net.Addr) (int, error) {
		if addr, ok := tgt.(*socks.Addr); ok {
			copy(b, addr.Addr)
			return len(addr.Addr), nil
		}
		if addr, ok := tgt.(*net.TCPAddr); ok {
			if ipv4 := addr.IP.To4(); ipv4 != nil {
				b[0] = socks.AddrTypeIPv4
				copy(b[1:], ipv4)
				b[1+net.IPv4len] = byte(addr.Port >> 8)
				b[1+net.IPv4len+1] = byte(addr.Port)
				return 1 + net.IPv4len + 2, nil
			}
			ipv6 := addr.IP.To16()
			b[0] = socks.AddrTypeIPv6
			copy(b[:1], ipv6)
			b[1+net.IPv6len] = byte(addr.Port >> 8)
			b[1+net.IPv6len+1] = byte(addr.Port)
			return 1 + net.IPv6len + 2, nil
		}
		return 0, errors.New("addr type error")
	}(buf, r.tgt)
	if err != nil {
		return 0, err
	}

	b[0] = byte(n >> 8)
	b[1] = byte(n)

	r.AEAD.Seal(b[:0], r.nonce, b[:2], nil)
	increment(r.nonce)

	r.AEAD.Seal(buf[:0], r.nonce, buf[:n], nil)
	increment(r.nonce)

	return saltSize + 2 + overhead + n + overhead, nil
}

// PacketReader is ...
type PacketReader struct {
	// Cipher is ...
	Cipher *core.Cipher
	// Reader is ...
	Reader gonet.PacketConn

	timeout time.Duration
}

// NewPacketReader is ...
func NewPacketReader(cipher *core.Cipher, conn gonet.PacketConn, timeout time.Duration) *PacketReader {
	r := &PacketReader{
		Cipher:  cipher,
		Reader:  conn,
		timeout: timeout,
	}
	return r
}

// Close is ...
func (r *PacketReader) Close() error {
	return nil
}

// Read is ...
func (r *PacketReader) Read(b []byte) (int, error) {
	// https://github.com/golang/net/blob/6772e930b67bb09bf22262c7378e7d2f67cf59d1/http2/transport.go#L646
	// https://github.com/golang/crypto/blob/master/internal/subtle/aliasing_purego.go#L18
	// the default buffer size is 16 << 10 - 1, to avoid overlap error when use aead cipher
	// use 512 for buffer for 2 + SaltSize + MaxAddrLen + Overhead
	headerLen := len(b)/2 + 512
	if len(b) < headerLen+2<<10 {
		return 0, io.ErrShortBuffer
	}
	r.Reader.SetReadDeadline(time.Now().Add(r.timeout))
	n, addr, err := r.Reader.ReadTo(b[headerLen:])
	if err != nil {
		return 0, err
	}
	offset, err := func(b []byte, tgt net.Addr) (int, error) {
		if addr, ok := tgt.(*socks.Addr); ok {
			offset := len(b) - len(addr.Addr)
			copy(b[offset:], addr.Addr)
			return offset, nil
		}
		if addr, ok := tgt.(*net.UDPAddr); ok {
			if ipv4 := addr.IP.To4(); ipv4 != nil {
				offset := len(b) - 1 - net.IPv4len - 2
				b = b[offset:]
				b[0] = socks.AddrTypeIPv4
				copy(b[1:], ipv4)
				b[1+net.IPv4len] = byte(addr.Port >> 8)
				b[1+net.IPv4len+1] = byte(addr.Port)
				return offset, nil
			}
			ipv6 := addr.IP.To16()
			offset := len(b) - 1 - net.IPv6len - 2
			b = b[offset:]
			b[0] = socks.AddrTypeIPv6
			copy(b[1:], ipv6)
			b[1+net.IPv6len] = byte(addr.Port >> 8)
			b[1+net.IPv6len+1] = byte(addr.Port)
			return offset, nil
		}
		return 0, errors.New("addr type error")
	}(b[:headerLen], addr)
	if err != nil {
		return 0, err
	}

	buf, err := func(dst, pkt []byte, cipher *core.Cipher) ([]byte, error) {
		saltSize := cipher.SaltSize
		salt := dst[:saltSize]
		_, err := rand.Read(salt)
		if err != nil {
			return nil, err
		}

		aead, err := cipher.NewAEAD(salt)
		if err != nil {
			return nil, err
		}

		if len(dst) < saltSize+len(pkt)+aead.Overhead() {
			return nil, io.ErrShortBuffer
		}

		return aead.Seal(dst[:saltSize], zerononce[:aead.NonceSize()], pkt, nil), nil
	}(b[2:], b[offset:headerLen+n], r.Cipher)
	b[0] = byte(len(buf) >> 8)
	b[1] = byte(len(buf))
	return 2 + len(buf), err
}
