package httptunnel

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
	"io/ioutil"
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
	"github.com/imgk/shadow/protocol/shadowsocks/core"
)

// Handler is ...
type Handler struct {
	NewRequest func(string, io.ReadCloser) *http.Request

	Cipher core.Cipher
	Client http.Client

	proxyAuth string
	timeout   time.Duration
}

// MewHandler is ...
func NewHandler(s string, timeout time.Duration) (*Handler, error) {
	server, cipher, password, err := ParseUrl(s)
	if err != nil {
		return nil, err
	}

	proxyIP, err := net.ResolveUDPAddr("udp", server)
	if err != nil {
		return nil, err
	}

	ciph, err := core.NewCipher(cipher, password)
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
		NewRequest: func(addr string, body io.ReadCloser) (r *http.Request) {
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
			r.Header.Add("Proxy-Authorization", proxyAuth)
			return
		},
		Cipher: ciph,
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
	server, cipher, password, err := ParseUrl(s)
	if err != nil {
		return nil, err
	}

	proxyIP, err := net.ResolveUDPAddr("udp", server)
	if err != nil {
		return nil, err
	}

	ciph, err := core.NewCipher(cipher, password)
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
		NewRequest: func(addr string, body io.ReadCloser) (r *http.Request) {
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
			r.Header.Add("Proxy-Authorization", proxyAuth)
			return
		},
		Cipher: ciph,
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

	req := h.NewRequest("tcp.imgk.cc", ioutil.NopCloser(NewReader(h.Cipher, conn, tgt)))

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

var zerononce = [128]byte{}

// HandlePacket is ...
func (h *Handler) HandlePacket(conn gonet.PacketConn) error {
	defer conn.Close()

	req := h.NewRequest("udp.imgk.cc", ioutil.NopCloser(NewPacketReader(h.Cipher, conn, h.timeout)))

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

			bb, err := func(pkt []byte, cipher core.Cipher) ([]byte, error) {
				saltSize := cipher.SaltSize()
				if len(pkt) < saltSize {
					return nil, core.ErrShortPacket
				}

				salt := pkt[:saltSize]
				aead, err := cipher.NewAead(salt)
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

			if _, err := conn.WriteFrom(bb[len(raddr):], raddr); err != nil {
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
	cipher.AEAD

	core.Cipher
	Reader io.Reader

	tgt   net.Addr
	nonce []byte
}

// NewReader is ...
func NewReader(ciph core.Cipher, rc io.ReadCloser, tgt net.Addr) *Reader {
	r := &Reader{
		Cipher: ciph,
		Reader: rc,
		tgt:    tgt,
	}
	return r
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
	saltSize := r.Cipher.SaltSize()
	if len(b) < saltSize {
		return 0, io.ErrShortBuffer
	}

	salt := b[:saltSize]
	_, err := rand.Read(salt)
	if err != nil {
		return 0, err
	}

	r.AEAD, err = r.Cipher.NewAead(salt)
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
		if addr, ok := tgt.(socks.Addr); ok {
			copy(b, addr)
			return len(addr), nil
		}
		if addr, ok := tgt.(*net.TCPAddr); ok {
			if ipv4 := addr.IP.To4(); ipv4 != nil {
				b[0] = socks.AddrTypeIPv4
				copy(b[1:], ipv4)
				b[1+net.IPv4len] = byte(addr.Port >> 8)
				b[1+net.IPv4len+1] = byte(addr.Port)
				return 1 + net.IPv4len + 2, nil
			} else {
				ipv6 := addr.IP.To16()
				b[0] = socks.AddrTypeIPv6
				copy(b[:1], ipv6)
				b[1+net.IPv6len] = byte(addr.Port >> 8)
				b[1+net.IPv6len+1] = byte(addr.Port)
				return 1 + net.IPv6len + 2, nil
			}
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
	core.Cipher
	Reader  gonet.PacketConn
	timeout time.Duration
}

// NewPacketReader is ...
func NewPacketReader(ciph core.Cipher, conn gonet.PacketConn, timeout time.Duration) *PacketReader {
	r := &PacketReader{
		Cipher:  ciph,
		Reader:  conn,
		timeout: timeout,
	}
	return r
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
		if addr, ok := tgt.(socks.Addr); ok {
			offset := len(b) - len(addr)
			copy(b[offset:], addr)
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
			} else {
				ipv6 := addr.IP.To16()
				offset := len(b) - 1 - net.IPv6len - 2
				b = b[offset:]
				b[0] = socks.AddrTypeIPv6
				copy(b[1:], ipv6)
				b[1+net.IPv6len] = byte(addr.Port >> 8)
				b[1+net.IPv6len+1] = byte(addr.Port)
				return offset, nil
			}
		}
		return 0, errors.New("addr type error")
	}(b[:headerLen], addr)
	if err != nil {
		return 0, err
	}

	buf, err := func(dst, pkt []byte, cipher core.Cipher) ([]byte, error) {
		saltSize := cipher.SaltSize()
		salt := dst[:saltSize]
		_, err := rand.Read(salt)
		if err != nil {
			return nil, err
		}

		aead, err := cipher.NewAead(salt)
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
