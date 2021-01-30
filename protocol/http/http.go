package http

import (
	"errors"
	"fmt"
	"io"
	"io/ioutil"
	"net"
	"net/http"

	"github.com/imgk/shadow/netstack"
)

type handler struct {
	NewRequest func(string, io.ReadCloser) *http.Request

	http.Client

	proxyAuth string
}

// Close is ...
func (h *handler) Close() error {
	return nil
}

// Handle is ...
func (h *handler) Handle(conn net.Conn, tgt net.Addr) error {
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
func (h *handler) HandlePacket(conn netstack.PacketConn) error {
	return errors.New("http proxy does not support UDP")
}
