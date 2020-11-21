// +build !shadow_cgo
// +build windows

package core

import (
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
	go func(r io.Reader, size int, ep *channel.Endpoint) {
		for {
			buf := make([]byte, size)
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
		pkt.SetChecksum(0)
		pkt.SetChecksum(^pkt.CalculateChecksum())
		switch ProtocolNumber := pkt.TransportProtocol(); ProtocolNumber {
		case header.UDPProtocolNumber:
			hdr := header.UDP(pkt.Payload())
			sum := header.PseudoHeaderChecksum(ProtocolNumber, pkt.DestinationAddress(), pkt.SourceAddress(), hdr.Length())
			sum = header.Checksum(hdr.Payload(), sum)
			hdr.SetChecksum(0)
			hdr.SetChecksum(^hdr.CalculateChecksum(sum))
		case header.TCPProtocolNumber:
			hdr := header.TCP(pkt.Payload())
			sum := header.PseudoHeaderChecksum(ProtocolNumber, pkt.DestinationAddress(), pkt.SourceAddress(), pkt.PayloadLength())
			sum = header.Checksum(hdr.Payload(), sum)
			hdr.SetChecksum(0)
			hdr.SetChecksum(^hdr.CalculateChecksum(sum))
		}
		e.Endpoint.InjectInbound(header.IPv4ProtocolNumber, &stack.PacketBuffer{
			Data: buffer.View(buf).ToVectorisedView(),
		})
	case header.IPv6Version:
		// WinDivert: need to calculate chekcsum
		pkt := header.IPv6(buf)
		switch ProtocolNumber := pkt.TransportProtocol(); ProtocolNumber {
		case header.UDPProtocolNumber:
			hdr := header.UDP(pkt.Payload())
			sum := header.PseudoHeaderChecksum(ProtocolNumber, pkt.DestinationAddress(), pkt.SourceAddress(), hdr.Length())
			sum = header.Checksum(hdr.Payload(), sum)
			hdr.SetChecksum(0)
			hdr.SetChecksum(^hdr.CalculateChecksum(sum))
		case header.TCPProtocolNumber:
			hdr := header.TCP(pkt.Payload())
			sum := header.PseudoHeaderChecksum(ProtocolNumber, pkt.DestinationAddress(), pkt.SourceAddress(), pkt.PayloadLength())
			sum = header.Checksum(hdr.Payload(), sum)
			hdr.SetChecksum(0)
			hdr.SetChecksum(^hdr.CalculateChecksum(sum))
		}
		e.Endpoint.InjectInbound(header.IPv6ProtocolNumber, &stack.PacketBuffer{
			Data: buffer.View(buf).ToVectorisedView(),
		})
	}
	return len(buf), nil
}
