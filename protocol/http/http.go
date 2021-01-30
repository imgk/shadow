package http

import (
	"crypto/tls"
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

	"github.com/imgk/shadow/netstack"
)

type h2Handler struct {
	// give new http.MethocConnect http.Request
	NewRequest func(string, io.ReadCloser) *http.Request

	// for connect to proxy server
	http.Client

	proxyAuth string
}

func newH2Handler(s string, timeout time.Duration) (*h2Handler, error) {
	auth, server, domain, scheme, err := ParseURL(s)
	if err != nil {
		return nil, err
	}

	if scheme == "http2" {
		handler := &h2Handler{
			NewRequest: func(addr string, body io.ReadCloser) *http.Request {
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
			},
			proxyAuth: auth,
		}
		return handler, nil
	}

	handler := &h2Handler{
		NewRequest: func(addr string, body io.ReadCloser) *http.Request {
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
				Dial: func(network, addr string, tlsCfg *tls.Config, cfg *quic.Config) (quic.EarlySession, error) {
					return quic.DialAddrEarly(server, tlsCfg, cfg)
				},
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
func (h *h2Handler) Close() error {
	return nil
}

// Handle is ...
func (h *h2Handler) Handle(conn net.Conn, tgt net.Addr) error {
	defer conn.Close()

	type Reader struct {
		io.Reader
	}

	req := h.NewRequest(tgt.String(), ioutil.NopCloser(&Reader{Reader: conn}))

	r, err := h.Client.Do(req)
	if err != nil {
		return fmt.Errorf("do request error: %w", err)
	}
	if r.StatusCode != http.StatusOK {
		return fmt.Errorf("response status code error: %v", r.StatusCode)
	}
	defer r.Body.Close()

	if _, err := io.Copy(conn, r.Body); err != nil {
		return fmt.Errorf("io.Copy error: %w", err)
	}
	return nil
}

// HandlePacket is ...
func (h *h2Handler) HandlePacket(conn netstack.PacketConn) error {
	return errors.New("http proxy does not support UDP")
}
