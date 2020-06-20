package balancer

import (
	"math/rand"
	"net"
	"sync"

	"github.com/imgk/shadow/netstack"
)

const url = "http://clients1.google.com/generate_204"

type Handler struct {
	sync.Mutex
	handler []netstack.Handler
}

func NewHandler(handler []netstack.Handler) *Handler {
	h := &Handler{
		Mutex: sync.Mutex{},
		handler: handler,
	}
	go h.checkHandler()
	return h
}

func (h *Handler) Handle(conn net.Conn, target net.Addr) error {
	return h.PickHandler().Handle(conn, target)
}

func (h *Handler) HandlePacket(conn netstack.PacketConn) error {
	return h.PickHandler().HandlePacket(conn)
}

func (h *Handler) PickHandler() netstack.Handler {
	return h.handler[int(rand.Uint32())%len(h.handler)]
}

func (h *Handler) checkHandler() {
	select {}
}
