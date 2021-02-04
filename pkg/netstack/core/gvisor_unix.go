// +build linux darwin

package core

import (
	"errors"
	"log"
	"sync"

	"gvisor.dev/gvisor/pkg/tcpip/buffer"
	"gvisor.dev/gvisor/pkg/tcpip/header"
	"gvisor.dev/gvisor/pkg/tcpip/link/channel"
	"gvisor.dev/gvisor/pkg/tcpip/stack"
)

// Device is a tun-like device for reading packets from system
type Device interface {
	Reader
	Writer
	DeviceType() string
}

// Endpoint is ...
type Endpoint struct {
	*channel.Endpoint
	Reader Reader
	Writer Writer

	mtu  int
	mu   sync.Mutex
	buff []byte
}

// NewEndpoint is ...
func NewEndpoint(dev Device, mtu int) stack.LinkEndpoint {
	wt, ok := dev.(Writer)
	if !ok {
		log.Panic(errors.New("not a valid tun for unix"))
	}
	rt, ok := dev.(Reader)
	if !ok {
		log.Panic(errors.New("not a valid tun for unix"))
	}
	ep := &Endpoint{
		Endpoint: channel.New(512, uint32(mtu), ""),
		Reader:   rt,
		Writer:   wt,
		mtu:      mtu,
		buff:     make([]byte, 4+mtu),
	}
	ep.Endpoint.AddNotify(ep)
	return ep
}

// Attach is to attach device to stack
func (e *Endpoint) Attach(dispatcher stack.NetworkDispatcher) {
	const Offset = 4

	e.Endpoint.Attach(dispatcher)
	go func(r Reader, size int, ep *channel.Endpoint) {
		for {
			buf := make([]byte, size)
			nr, err := r.Read(buf, Offset)
			if err != nil {
				break
			}
			buf = buf[Offset:]

			switch header.IPVersion(buf) {
			case header.IPv4Version:
				ep.InjectInbound(header.IPv4ProtocolNumber, &stack.PacketBuffer{
					Data: buffer.View(buf[:nr]).ToVectorisedView(),
				})
			case header.IPv6Version:
				ep.InjectInbound(header.IPv6ProtocolNumber, &stack.PacketBuffer{
					Data: buffer.View(buf[:nr]).ToVectorisedView(),
				})
			}
		}
	}(e.Reader, Offset+e.mtu, e.Endpoint)
}

// WriteNotify is to write packets back to system
func (e *Endpoint) WriteNotify() {
	const Offset = 4

	info, ok := e.Endpoint.Read()
	if !ok {
		return
	}

	e.mu.Lock()
	buf := append(e.buff[:Offset], info.Pkt.NetworkHeader().View()...)
	buf = append(buf, info.Pkt.TransportHeader().View()...)
	buf = append(buf, info.Pkt.Data.ToView()...)
	e.Writer.Write(buf, Offset)
	e.mu.Unlock()
}

// Writer is for linux tun writing with 4 bytes prefix
type Writer interface {
	Write([]byte, int) (int, error)
}
