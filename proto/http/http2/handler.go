package http2

import (
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

// Hander is ...
type Handler struct {
	// NewRequest is ...
	// give new http.MethocConnect http.Request
	NewRequest func(string, io.ReadCloser, string) *http.Request

	// Transport is ...
	// for connect to proxy server
	Transport http.RoundTripper

	proxyAuth string
}

// NewHandler is ...
func NewHandler(s string, timeout time.Duration) (*Handler, error) {
	auth, server, domain, scheme, err := ParseURL(s)
	if err != nil {
		return nil, err
	}

	if scheme == "http2" {
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
					ServerName:         domain,
					ClientSessionCache: tls.NewLRUClientSessionCache(32),
				},
			},
			proxyAuth: auth,
		}
		return handler, nil
	}

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
		Transport: &http3.RoundTripper{
			Dial: func(network, addr string, tlsCfg *tls.Config, cfg *quic.Config) (quic.EarlySession, error) {
				return quic.DialAddrEarly(server, tlsCfg, cfg)
			},
			TLSClientConfig: &tls.Config{
				ServerName:         domain,
				ClientSessionCache: tls.NewLRUClientSessionCache(32),
			},
			QuicConfig: &quic.Config{KeepAlive: true},
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
func (h *Handler) Handle(conn net.Conn, tgt net.Addr) error {
	defer conn.Close()

	req := h.NewRequest(tgt.String(), &Reader{Reader: conn}, h.proxyAuth)

	r, err := h.Transport.RoundTrip(req)
	if err != nil {
		return fmt.Errorf("do request error: %w", err)
	}
	defer r.Body.Close()
	if r.StatusCode != http.StatusOK {
		return fmt.Errorf("response status code error: %v", r.StatusCode)
	}

	if _, err := io.Copy(conn, r.Body); err != nil {
		return fmt.Errorf("io.Copy error: %w", err)
	}
	return nil
}

// HandlePacket is ...
func (h *Handler) HandlePacket(conn gonet.PacketConn) error {
	return errors.New("http proxy does not support UDP")
}

// Reader is ...
type Reader struct {
	io.Reader
}

// Close is ...
func (r *Reader) Close() error {
	return nil
}
