package online

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io/ioutil"
	"net"
	"net/http"
	"net/url"
	"sync"
	"time"

	"golang.org/x/time/rate"

	"github.com/imgk/shadow/common"
	"github.com/imgk/shadow/protocol"
)

type OnlineHandler struct {
	Handler common.Handler
	URL     string
	timeout time.Duration
	limiter *rate.Limiter
	mu      sync.Mutex
	closed  chan struct{}
}

func NewOnlineHandler(s string, timeout time.Duration) (*OnlineHandler, error) {
	handler := &OnlineHandler{timeout: timeout, closed: make(chan struct{})}
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

func (h *OnlineHandler) renewLoop() {
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

func (h *OnlineHandler) tryRenew() (err error) {
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
	addr := func() common.Addr {
		addr := "connectivitycheck.gstatic.com"
		b := make([]byte, 0, common.MaxAddrLen)
		b = append(b, common.AddrTypeDomain)
		b = append(b, byte(len(addr)))
		b = append(b, []byte(addr)...)
		b = append(b, 0, 80)
		return common.Addr(b[:1+1+len(addr)+2])
	}()

	h.mu.Lock()
	handler := h.Handler
	h.mu.Unlock()
	if handler == nil {
		err = errors.New("no valid handler")
		return
	}
	go handler.Handle(rc, addr)

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

func (h *OnlineHandler) renew() error {
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
	if r.StatusCode != http.StatusOK {
		return errors.New("http response code error")
	}
	defer r.Body.Close()

	b, err := ioutil.ReadAll(r.Body)
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

		handler, err := protocol.NewHandler(addr, h.timeout)
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

func (h *OnlineHandler) Close() error {
	close(h.closed)
	return nil
}

func (h *OnlineHandler) Handle(conn net.Conn, tgt net.Addr) error {
	h.mu.Lock()
	handler := h.Handler
	h.mu.Unlock()

	err := handler.Handle(conn, tgt)
	if err != nil && h.limiter.Allow() {
		go h.tryRenew()
	}
	return err
}

func (h *OnlineHandler) HandlePacket(conn common.PacketConn) error {
	h.mu.Lock()
	handler := h.Handler
	h.mu.Unlock()

	err := handler.HandlePacket(conn)
	if err != nil && h.limiter.Allow() {
		go h.tryRenew()
	}
	return err
}
