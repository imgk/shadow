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

	"github.com/imgk/shadow/common"
	"github.com/imgk/shadow/protocol/shadowsocks/core"
)

type Handler struct {
	Cipher    core.Cipher
	Client    http.Client
	proxyAuth string
	timeout   time.Duration
}

func NewHandler(url string, timeout time.Duration) (*Handler, error) {
	server, cipher, password, err := ParseUrl(url)
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

func NewQUICHandler(url string, timeout time.Duration) (*Handler, error) {
	server, cipher, password, err := ParseUrl(url)
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
			},
		},
		proxyAuth: proxyAuth,
		timeout:   timeout,
	}, nil
}

func (h *Handler) NewRequest(method, addr string, body io.ReadCloser) (r *http.Request, err error) {
	if _, ok := h.Client.Transport.(*http2.Transport); ok {
		r = &http.Request{
			Method: method,
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
		r.Header.Add("Proxy-Authorization", h.proxyAuth)
		return
	}

	r = &http.Request{
		Method: method,
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
	r.Header.Add("Proxy-Authorization", h.proxyAuth)
	return
}

func (h *Handler) Close() error {
	return nil
}

func (h *Handler) Handle(conn net.Conn, tgt net.Addr) error {
	defer conn.Close()

	req, err := h.NewRequest(http.MethodConnect, "tcp.imgk.cc", ioutil.NopCloser(NewReader(h.Cipher, conn, tgt)))
	if err != nil {
		return fmt.Errorf("NewRequest error: %v", err)
	}

	r, err := h.Client.Do(req)
	if err != nil {
		return fmt.Errorf("do request error: %v", err)
	}
	if r.StatusCode != http.StatusOK {
		return fmt.Errorf("response status code error: %v", r.StatusCode)
	}
	if _, err := core.NewReader(r.Body, h.Cipher).WriteTo(io.Writer(conn)); err != nil {
		return fmt.Errorf("WriteTo error: %v", err)
	}
	return nil
}

var zerononce = [128]byte{}

func (h *Handler) HandlePacket(conn common.PacketConn) error {
	defer conn.Close()

	req, err := h.NewRequest(http.MethodConnect, "udp.imgk.cc", ioutil.NopCloser(NewPacketReader(h.Cipher, conn, h.timeout)))
	if err != nil {
		return fmt.Errorf("NewRequest error: %v", err)
	}

	r, err := h.Client.Do(req)
	if err != nil {
		return fmt.Errorf("do request error: %v", err)
	}
	if r.StatusCode != http.StatusOK {
		return fmt.Errorf("response status code error: %v", r.StatusCode)
	}

	err = func(r io.Reader) error {
		slice := common.Get()
		defer common.Put(slice)
		b := slice.Get()

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

			raddr, err := common.ParseAddr(bb)
			if err != nil {
				return fmt.Errorf("parse common.Addr error: %v", err)
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

type Reader struct {
	cipher.AEAD

	core.Cipher
	Reader io.Reader

	tgt   net.Addr
	nonce []byte
}

func NewReader(ciph core.Cipher, rc io.ReadCloser, tgt net.Addr) *Reader {
	r := &Reader{
		Cipher: ciph,
		Reader: rc,
		tgt:    tgt,
	}
	return r
}

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
	if len(b) < saltSize+2+overhead+common.MaxAddrLen+overhead {
		return 0, io.ErrShortBuffer
	}

	b = b[saltSize:]
	buf := b[2+overhead:]

	n, err := func(b []byte, tgt net.Addr) (int, error) {
		if addr, ok := tgt.(common.Addr); ok {
			copy(b, addr)
			return len(addr), nil
		}
		if addr, ok := tgt.(*net.TCPAddr); ok {
			if ipv4 := addr.IP.To4(); ipv4 != nil {
				b[0] = common.AddrTypeIPv4
				copy(b[1:], ipv4)
				b[1+net.IPv4len] = byte(addr.Port >> 8)
				b[1+net.IPv4len+1] = byte(addr.Port)
				return 1 + net.IPv4len + 2, nil
			} else {
				ipv6 := addr.IP.To16()
				b[0] = common.AddrTypeIPv6
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

type PacketReader struct {
	core.Cipher
	Reader  common.PacketConn
	timeout time.Duration
}

func NewPacketReader(ciph core.Cipher, conn common.PacketConn, timeout time.Duration) *PacketReader {
	r := &PacketReader{
		Cipher:  ciph,
		Reader:  conn,
		timeout: timeout,
	}
	return r
}

func (r *PacketReader) Read(b []byte) (int, error) {
	headerLen := 2 + r.Cipher.SaltSize() + common.MaxAddrLen
	if len(b) < headerLen {
		return 0, io.ErrShortBuffer
	}
	r.Reader.SetReadDeadline(time.Now().Add(r.timeout))
	n, addr, err := r.Reader.ReadTo(b[headerLen:])
	if err != nil {
		return 0, err
	}
	offset, err := func(b []byte, tgt net.Addr) (int, error) {
		if addr, ok := tgt.(common.Addr); ok {
			offset := len(b) - len(addr)
			copy(b[offset:], addr)
			return offset, nil
		}
		if addr, ok := tgt.(*net.UDPAddr); ok {
			if ipv4 := addr.IP.To4(); ipv4 != nil {
				offset := len(b) - 1 - net.IPv4len - 2
				b = b[offset:]
				b[0] = common.AddrTypeIPv4
				copy(b[1:], ipv4)
				b[1+net.IPv4len] = byte(addr.Port >> 8)
				b[1+net.IPv4len+1] = byte(addr.Port)
				return offset, nil
			} else {
				ipv6 := addr.IP.To16()
				offset := len(b) - 1 - net.IPv6len - 2
				b = b[offset:]
				b[0] = common.AddrTypeIPv6
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

	buf, err := core.Pack(b[2:], b[offset:headerLen+n], r.Cipher)
	b[0] = byte(len(buf) >> 8)
	b[1] = byte(len(buf))
	return 2 + len(buf), err
}
