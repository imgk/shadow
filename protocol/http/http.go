package http

import (
	"errors"
	"fmt"
	"io"
	"io/ioutil"
	"net"
	"net/http"
	"net/url"

	"golang.org/x/net/http2"

	"github.com/imgk/shadow/netstack"
)

type handler struct {
	http.Client
	auth string
}

// Close is ...
func (h *handler) Close() error {
	return nil
}

func (h *handler) NewRequest(method, addr string, body io.ReadCloser) (r *http.Request, err error) {
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
		r.Header.Add("Proxy-Authorization", h.auth)
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
	r.Header.Add("Proxy-Authorization", h.auth)
	return
}

// Handle is ...
func (h *handler) Handle(conn net.Conn, tgt net.Addr) error {
	defer conn.Close()

	req, err := h.NewRequest(http.MethodConnect, tgt.String(), ioutil.NopCloser(&Reader{Reader: conn}))
	if err != nil {
		return fmt.Errorf("NewRequest error: %w", err)
	}

	r, err := h.Client.Do(req)
	if err != nil {
		return fmt.Errorf("do request error: %w", err)
	}
	if r.StatusCode != http.StatusOK {
		return fmt.Errorf("response status code error: %v", r.StatusCode)
	}
	if _, err := io.Copy(conn, r.Body); err != nil {
		return fmt.Errorf("io.Copy error: %w", err)
	}
	return nil
}

// HandlePacket is ...
func (h *handler) HandlePacket(conn netstack.PacketConn) error {
	return errors.New("http proxy does not support UDP")
}

type Reader struct {
	io.Reader
}
