package online

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/url"
	"sync"
	"time"

	"golang.org/x/time/rate"

	"github.com/imgk/shadow/pkg/gonet"
	"github.com/imgk/shadow/pkg/socks"
)

// Handler is ...
type Handler struct {
	// Handler is ...
	Handler gonet.Handler
	// URL is ...
	URL string

	timeout time.Duration

	mu      sync.Mutex
	limiter *rate.Limiter
	closed  chan struct{}
}

// NewHandler is ...
func NewHandler(s string, timeout time.Duration) (*Handler, error) {
	handler := &Handler{timeout: timeout, closed: make(chan struct{})}
	handler.limiter = rate.NewLimiter(rate.Every(time.Minute), 1)

	uri, err := url.Parse(s)
	if err != nil {
		return nil, err
	}
	uri.Scheme = "https"
	handler.URL = uri.String()

	go handler.renewLoop()

	return handler, handler.renew()
}

func (h *Handler) renewLoop() {
	t := time.NewTicker(time.Hour)
	defer t.Stop()

	for {
		select {
		case <-t.C:
			h.renew()
		case <-h.closed:
			return
		}
	}
}

func (h *Handler) tryRenew() (err error) {
	defer func() {
		if err != nil {
			h.renew()
		}
	}()

	c, rc := net.Pipe()
	defer func() {
		c.SetDeadline(time.Now())
		rc.SetDeadline(time.Now())
		c.Close()
		rc.Close()
	}()
	t := http.Transport{
		DialContext: func(ctx context.Context, network, addr string) (net.Conn, error) {
			return c, nil
		},
		Dial: func(network, addr string) (net.Conn, error) {
			return c, nil
		},
	}
	addr := func() *socks.Addr {
		addr := "connectivitycheck.gstatic.com"
		b := make([]byte, 0, socks.MaxAddrLen)
		b = append(b, socks.AddrTypeDomain)
		b = append(b, byte(len(addr)))
		b = append(b, []byte(addr)...)
		b = append(b, 0, 80)
		return &socks.Addr{Addr: b[:1+1+len(addr)+2]}
	}()

	h.mu.Lock()
	handler := h.Handler
	h.mu.Unlock()
	if handler == nil {
		err = errors.New("no valid handler")
		return
	}
	go handler.Handle(gonet.NewConn(rc), addr)

	req, err := http.NewRequest(http.MethodGet, "http://connectivitycheck.gstatic.com/generate_204", nil)
	if err != nil {
		return
	}
	r, err := t.RoundTrip(req)
	if err != nil {
		return
	}
	if r.StatusCode != http.StatusNoContent {
		err = errors.New("status code error")
		return
	}
	return
}

func (h *Handler) renew() error {
	type OnlineConfig struct {
		Version int `json:"version"`
		Servers []*struct {
			ID            string `json:"id"`
			Remarks       string `json:"remarks"`
			Server        string `json:"server"`
			ServerPort    int    `json:"server_port"`
			Password      string `json:"password"`
			Method        string `json:"method"`
			Plugin        string `json:"plugin"`
			PluginOptions string `json:"plugin_opts"`

			// for other protocol, ss, ss-tls and else
			// TODO: support http/https and trojan
			Protocol string `json:"protocol,omitempty"`
		} `json:"servers"`
		BytesUsed      uint64 `json:"bytes_used,omitempty"`
		BytesRemaining uint64 `json:"bytes_remaining,omitempty"`
		DaysUsed       uint64 `json:"days_used"`
		DaysRemaining  uint64 `json:"days_remaining"`
	}

	r, err := http.Get(h.URL)
	if err != nil {
		return err
	}
	defer r.Body.Close()
	if r.StatusCode != http.StatusOK {
		return errors.New("http response code error")
	}

	b, err := io.ReadAll(r.Body)
	if err != nil {
		return err
	}

	config := OnlineConfig{}
	if err := json.Unmarshal(b, &config); err != nil {
		return err
	}
	if config.Version != 1 {
		return errors.New("online config version error")
	}

	for _, server := range config.Servers {
		if server.Protocol == "" {
			server.Protocol = "ss"
		}
		addr := fmt.Sprintf("%v://%v:%v@%v:%v", server.Protocol, server.Method, server.Password, server.Server, server.ServerPort)

		handler, err := NewHandler(addr, h.timeout)
		if err != nil {
			continue
		}

		h.mu.Lock()
		h.Handler = handler
		h.mu.Unlock()
		return nil
	}

	return errors.New("no valiad server")
}

// Close is ...
func (h *Handler) Close() error {
	close(h.closed)
	return nil
}

// Handle is ...
func (h *Handler) Handle(conn gonet.Conn, tgt net.Addr) error {
	h.mu.Lock()
	handler := h.Handler
	h.mu.Unlock()

	err := handler.Handle(conn, tgt)
	if err != nil && h.limiter.Allow() {
		go h.tryRenew()
	}
	return err
}

// HandlePacket i s...
func (h *Handler) HandlePacket(conn gonet.PacketConn) error {
	h.mu.Lock()
	handler := h.Handler
	h.mu.Unlock()

	err := handler.HandlePacket(conn)
	if err != nil && h.limiter.Allow() {
		go h.tryRenew()
	}
	return err
}
