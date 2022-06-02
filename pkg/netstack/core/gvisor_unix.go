//go:build linux || darwin

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
	// Reader is ...
	Reader
	// Writer is ...
	Writer
	// DeviceType is ...
	// give device type
	DeviceType() string
}

// Endpoint is ...
type Endpoint struct {
	// Endpoint is ...
	*channel.Endpoint
	// Reader is ...
	// read packets from tun device
	Reader Reader
	// Writer is ...
	// write packets to tun device
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

			pktBuffer := stack.NewPacketBuffer(stack.PacketBufferOptions{
				ReserveHeaderBytes: 0,
				Data:               buffer.View(buf[:nr]).ToVectorisedView(),
			})
			switch header.IPVersion(buf) {
			case header.IPv4Version:
				ep.InjectInbound(header.IPv4ProtocolNumber, pktBuffer)
			case header.IPv6Version:
				ep.InjectInbound(header.IPv6ProtocolNumber, pktBuffer)
			}
			pktBuffer.DecRef()
		}
	}(e.Reader, Offset+e.mtu, e.Endpoint)
}

// WriteNotify is to write packets back to system
func (e *Endpoint) WriteNotify() {
	const Offset = 4

	pkt := e.Endpoint.Read()

	e.mu.Lock()
	buf := append(e.buff[:Offset], pkt.NetworkHeader().View()...)
	buf = append(buf, pkt.TransportHeader().View()...)
	vv := pkt.Data().ExtractVV()
	buf = append(buf, vv.ToView()...)
	e.Writer.Write(buf, Offset)
	e.mu.Unlock()
}

// Writer is for linux tun writing with 4 bytes prefix
type Writer interface {
	// Write packets to tun device
	Write([]byte, int) (int, error)
}
