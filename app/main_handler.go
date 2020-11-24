package app

import (
	"fmt"
	"io"
	"math/rand"
	"net"
	"net/http"
	"sync"

	"github.com/imgk/shadow/common"
)

type Conn struct {
	io.Closer
	Network    string
	LocalAddr  net.Addr
	RemoteAddr net.Addr
}

type Handler struct {
	common.Handler

	mu    sync.RWMutex
	conns map[uint32]*Conn
}

func NewHandler(h common.Handler) *Handler {
	hd := &Handler{
		Handler: h,
		conns:   make(map[uint32]*Conn),
	}
	http.Handle("/admin/conns", hd)
	return hd
}

func (h *Handler) Handle(conn net.Conn, addr net.Addr) (err error) {
	key := rand.Uint32()

	h.mu.Lock()
	h.conns[key] = &Conn{Closer: conn, Network: "TCP", LocalAddr: conn.RemoteAddr(), RemoteAddr: addr}
	h.mu.Unlock()

	err = h.Handler.Handle(conn, addr)

	h.mu.Lock()
	delete(h.conns, key)
	h.mu.Unlock()

	return
}

func (h *Handler) HandlePacket(conn common.PacketConn) (err error) {
	key := rand.Uint32()

	h.mu.Lock()
	h.conns[key] = &Conn{Closer: conn, Network: "UDP", LocalAddr: conn.RemoteAddr(), RemoteAddr: conn.LocalAddr()}
	h.mu.Unlock()

	err = h.Handler.HandlePacket(conn)

	h.mu.Lock()
	delete(h.conns, key)
	h.mu.Unlock()

	return
}

func (h *Handler) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	h.mu.RLock()
	for _, c := range h.conns {
		fmt.Fprintf(w, "%-25v<-%s->\t%v\n", c.LocalAddr, c.Network, c.RemoteAddr)
	}
	h.mu.RUnlock()
}
