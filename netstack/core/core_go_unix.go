// +build shadow_gvisor,linux shadow_gvisor,darwin

package core

import (
	"sync"

	"gvisor.dev/gvisor/pkg/tcpip/buffer"
	"gvisor.dev/gvisor/pkg/tcpip/header"
	"gvisor.dev/gvisor/pkg/tcpip/link/channel"
	"gvisor.dev/gvisor/pkg/tcpip/stack"
)

type Endpoint struct {
	*channel.Endpoint
	mtu int
	dev Device
	buf []byte
	mu  sync.Mutex
	wt  WriterOffset
}

func NewEndpoint(dev Device, mtu int) stack.LinkEndpoint {
	ep := &Endpoint{
		Endpoint: channel.New(512, uint32(mtu), ""),
		dev:      dev,
		mtu:      mtu,
		buf:      make([]byte, 4+mtu),
		wt:       dev.(WriterOffset),
	}
	ep.Endpoint.AddNotify(ep)
	return ep
}

func (e *Endpoint) Attach(dispatcher stack.NetworkDispatcher) {
	e.Endpoint.Attach(dispatcher)

	r, ok := e.dev.(ReaderOffset)
	if !ok {
		return
	}
	go func(r ReaderOffset, size int, ep *channel.Endpoint) {
		for {
			buf := make([]byte, size)
			n, err := r.ReadOffset(buf, 4)
			if err != nil {
				break
			}
			buf = buf[4 : 4+n]

			switch header.IPVersion(buf) {
			case header.IPv4Version:
				ep.InjectInbound(header.IPv4ProtocolNumber, &stack.PacketBuffer{
					Data: buffer.View(buf).ToVectorisedView(),
				})
			case header.IPv6Version:
				ep.InjectInbound(header.IPv6ProtocolNumber, &stack.PacketBuffer{
					Data: buffer.View(buf).ToVectorisedView(),
				})
			}
		}
	}(r, 4+e.mtu, e.Endpoint)
}

func (e *Endpoint) WriteNotify() {
	info, ok := e.Endpoint.Read()
	if !ok {
		return
	}

	e.mu.Lock()
	buf := append(e.buf[:4], info.Pkt.NetworkHeader().View()...)
	buf = append(buf, info.Pkt.TransportHeader().View()...)
	buf = append(buf, info.Pkt.Data.ToView()...)
	e.wt.WriteOffset(buf, 4)
	e.mu.Unlock()
}

type ReaderOffset interface {
	ReadOffset([]byte, int) (int, error)
}

type WriterOffset interface {
	WriteOffset([]byte, int) (int, error)
}
