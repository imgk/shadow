package http2

import (
	"context"
	"crypto/tls"
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
)

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
func (d *QUICDialer) Dial(ctx context.Context, network, addr string, tlsCfg *tls.Config, cfg *quic.Config) (quic.EarlyConnection, error) {
	return quic.DialAddrEarly(d.Addr, tlsCfg, cfg)
}

// Hander is ...
type Handler struct {
	// NewRequest is ...
	// give new http.MethocConnect http.Request
	NewRequest func(string, io.ReadCloser, string) *http.Request

	// Client is ...
	// for connect to proxy server
	Client http.Client

	proxyAuth string
}

// NewHandler is ...
func NewHandler(s string, timeout time.Duration) (*Handler, error) {
	auth, server, domain, scheme, err := ParseURL(s)
	if err != nil {
		return nil, err
	}

	if scheme == "http2" {
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
				if auth != "" {
					r.Header.Add("Proxy-Authorization", auth)
				}
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
		}
		return handler, nil
	}

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
			if auth != "" {
				r.Header.Add("Proxy-Authorization", auth)
			}
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
	}
	return handler, nil
}

// Close is ...
func (h *Handler) Close() error {
	return nil
}

// Handle is ...
func (h *Handler) Handle(conn gonet.Conn, tgt net.Addr) error {
	defer conn.Close()

	rc := NewReader(conn)
	req := h.NewRequest(tgt.String(), rc, h.proxyAuth)

	r, err := h.Client.Do(req)
	if err != nil {
		return fmt.Errorf("do request error: %w", err)
	}
	defer r.Body.Close()
	if r.StatusCode != http.StatusOK {
		return fmt.Errorf("response status code error: %v", r.StatusCode)
	}

	if _, err := gonet.Copy(conn, r.Body); err != nil {
		conn.CloseWrite()
		rc.Wait()
		return fmt.Errorf("gonet.Copy error: %w", err)
	}
	conn.CloseWrite()
	rc.Wait()
	return nil
}

// HandlePacket is ...
func (h *Handler) HandlePacket(conn gonet.PacketConn) error {
	return errors.New("http proxy does not support UDP")
}

// Reader is ...
type Reader struct {
	io.Reader
	closed chan struct{}
}

// NewReader is ...
func NewReader(r io.Reader) *Reader {
	reader := &Reader{
		Reader: r,
		closed: make(chan struct{}),
	}
	return reader
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
