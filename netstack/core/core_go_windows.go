// +build shadow_gvisor,windows

package core

import (
	"C" // avoiding error: "too many .rsrc sections"
	"io"
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
	wt  io.Writer
}

func NewEndpoint(dev Device, mtu int) stack.LinkEndpoint {
	ep := &Endpoint{
		Endpoint: channel.New(512, uint32(mtu), ""),
		dev:      dev,
		mtu:      mtu,
		buf:      make([]byte, mtu),
		wt:       dev.(io.Writer),
	}
	ep.Endpoint.AddNotify(ep)
	return ep
}

func (e *Endpoint) Attach(dispatcher stack.NetworkDispatcher) {
	e.Endpoint.Attach(dispatcher)

	r, ok := e.dev.(io.Reader)
	if !ok {
		go func(w *Endpoint, wt io.WriterTo) {
			if _, err := wt.WriteTo(w); err != nil {
				return
			}
		}(e, e.dev)
		return
	}
	go func(r io.Reader, mtu int, ep *channel.Endpoint) {
		for {
			buf := make([]byte, mtu)
			n, err := r.Read(buf)
			if err != nil {
				break
			}
			buf = buf[:n]

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
	}(r, e.mtu, e.Endpoint)
}

func (e *Endpoint) WriteNotify() {
	info, ok := e.Endpoint.Read()
	if !ok {
		return
	}

	e.mu.Lock()
	buf := append(e.buf[:0], info.Pkt.NetworkHeader().View()...)
	buf = append(buf, info.Pkt.TransportHeader().View()...)
	buf = append(buf, info.Pkt.Data.ToView()...)
	e.wt.Write(buf)
	e.mu.Unlock()
}

func (e *Endpoint) Write(b []byte) (int, error) {
	buf := append(make([]byte, 0, len(b)), b...)

	switch header.IPVersion(buf) {
	case header.IPv4Version:
		// WinDivert: need to calculate chekcsum
		pkt := header.IPv4(buf)
		pkt.SetChecksum(^pkt.CalculateChecksum())
		e.Endpoint.InjectInbound(header.IPv4ProtocolNumber, &stack.PacketBuffer{
			Data: buffer.View(buf).ToVectorisedView(),
		})
	case header.IPv6Version:
		// no checksum for ipv6
		e.Endpoint.InjectInbound(header.IPv6ProtocolNumber, &stack.PacketBuffer{
			Data: buffer.View(buf).ToVectorisedView(),
		})
	}
	return len(buf), nil
}
