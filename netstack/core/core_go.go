// +build !shadow_cgo

package core

import (
	"errors"
	"fmt"
	"io"
	"net"
	"sync"
	"time"

	"golang.org/x/time/rate"

	"go.uber.org/zap"
	"gvisor.dev/gvisor/pkg/tcpip"
	"gvisor.dev/gvisor/pkg/tcpip/adapters/gonet"
	"gvisor.dev/gvisor/pkg/tcpip/buffer"
	"gvisor.dev/gvisor/pkg/tcpip/header"
	"gvisor.dev/gvisor/pkg/tcpip/network/ipv4"
	"gvisor.dev/gvisor/pkg/tcpip/network/ipv6"
	"gvisor.dev/gvisor/pkg/tcpip/stack"
	"gvisor.dev/gvisor/pkg/tcpip/transport/icmp"
	"gvisor.dev/gvisor/pkg/tcpip/transport/tcp"
	"gvisor.dev/gvisor/pkg/tcpip/transport/udp"
	"gvisor.dev/gvisor/pkg/waiter"
)

type Stack struct {
	*zap.Logger
	Device  Device
	Handler Handler
	Stack   *stack.Stack

	mtu   int32
	mutex sync.Mutex
	conns map[string]*UDPConn
}

func (s *Stack) Start(device Device, handler Handler, logger *zap.Logger) (err error) {
	s.Logger = logger

	s.Device = device
	s.Handler = handler
	s.Stack = stack.New(stack.Options{
		NetworkProtocols: []stack.NetworkProtocolFactory{
			ipv4.NewProtocol,
			ipv6.NewProtocol,
		},
		TransportProtocols: []stack.TransportProtocolFactory{
			tcp.NewProtocol,
			udp.NewProtocol,
			icmp.NewProtocol4,
			icmp.NewProtocol6,
		},
	})
	defer func(s *stack.Stack) {
		if err != nil {
			s.Close()
		}
	}(s.Stack)

	const NICID = tcpip.NICID(1)

	// WithDefaultTTL sets the default TTL used by stack.
	{
		opt := tcpip.DefaultTTLOption(64)
		if tcperr := s.Stack.SetNetworkProtocolOption(ipv4.ProtocolNumber, &opt); tcperr != nil {
			err = fmt.Errorf("set ipv4 default TTL: %s", tcperr)
			return
		}
		if tcperr := s.Stack.SetNetworkProtocolOption(ipv6.ProtocolNumber, &opt); tcperr != nil {
			fmt.Errorf("set ipv6 default TTL: %s", tcperr)
			return
		}
	}

	// set forwarding
	if tcperr := s.Stack.SetForwarding(ipv4.ProtocolNumber, true); tcperr != nil {
		err = fmt.Errorf("set ipv4 forwarding error: %s", tcperr)
		return
	}
	if tcperr := s.Stack.SetForwarding(ipv6.ProtocolNumber, true); tcperr != nil {
		err = fmt.Errorf("set ipv6 forwarding error: %s", tcperr)
		return
	}

	// WithICMPBurst sets the number of ICMP messages that can be sent
	// in a single burst.
	s.Stack.SetICMPBurst(50)

	// WithICMPLimit sets the maximum number of ICMP messages permitted
	// by rate limiter.
	s.Stack.SetICMPLimit(rate.Limit(1000))

	// WithTCPBufferSizeRange sets the receive and send buffer size range for TCP.
	{
		rcvOpt := tcpip.TCPReceiveBufferSizeRangeOption{Min: 4 << 10, Default: 212 << 10, Max: 4 << 20}
		if tcperr := s.Stack.SetTransportProtocolOption(tcp.ProtocolNumber, &rcvOpt); tcperr != nil {
			err = fmt.Errorf("set TCP receive buffer size range: %s", tcperr)
			return
		}
		sndOpt := tcpip.TCPSendBufferSizeRangeOption{Min: 4 << 10, Default: 212 << 10, Max: 4 << 20}
		if tcperr := s.Stack.SetTransportProtocolOption(tcp.ProtocolNumber, &sndOpt); tcperr != nil {
			err = fmt.Errorf("set TCP send buffer size range: %s", tcperr)
			return
		}
	}

	// WithTCPCongestionControl sets the current congestion control algorithm.
	{
		opt := tcpip.CongestionControlOption("reno")
		if tcperr := s.Stack.SetTransportProtocolOption(tcp.ProtocolNumber, &opt); tcperr != nil {
			err = fmt.Errorf("set TCP congestion control algorithm: %s", tcperr)
			return
		}
	}

	// WithTCPModerateReceiveBuffer sets receive buffer moderation for TCP.
	{
		opt := tcpip.TCPDelayEnabled(false)
		if tcperr := s.Stack.SetTransportProtocolOption(tcp.ProtocolNumber, &opt); tcperr != nil {
			err = fmt.Errorf("set TCP delay: %s", err)
			return
		}
	}

	// WithTCPModerateReceiveBuffer sets receive buffer moderation for TCP.
	{
		opt := tcpip.TCPModerateReceiveBufferOption(true)
		if tcperr := s.Stack.SetTransportProtocolOption(tcp.ProtocolNumber, &opt); tcperr != nil {
			err = fmt.Errorf("set TCP moderate receive buffer: %s", tcperr)
			return
		}
	}

	// WithTCPSACKEnabled sets the SACK option for TCP.
	{
		opt := tcpip.TCPSACKEnabled(true)
		if tcperr := s.Stack.SetTransportProtocolOption(tcp.ProtocolNumber, &opt); tcperr != nil {
			err = fmt.Errorf("set TCP SACK: %s", tcperr)
			return
		}
	}

	mustSubnet := func(s string) tcpip.Subnet {
		_, ipNet, err := net.ParseCIDR(s)
		if err != nil {
			panic(fmt.Errorf("unable to ParseCIDR(%s): %w", s, err))
		}

		subnet, err := tcpip.NewSubnet(tcpip.Address(ipNet.IP), tcpip.AddressMask(ipNet.Mask))
		if err != nil {
			panic(fmt.Errorf("unable to NewSubnet(%s): %w", ipNet, err))
		}
		return subnet
	}

	// Add default route table for IPv4 and IPv6
	// This will handle all incoming ICMP packets.
	s.Stack.SetRouteTable([]tcpip.Route{
		{
			Destination: mustSubnet("0.0.0.0/0"),
			NIC:         NICID,
		},
		{
			Destination: mustSubnet("::/0"),
			NIC:         NICID,
		},
	})

	// Important: We must initiate transport protocol handlers
	// before creating NIC, otherwise NIC would dispatch packets
	// to stack and cause race condition.
	s.Stack.SetTransportProtocolHandler(tcp.ProtocolNumber, tcp.NewForwarder(s.Stack, 16<<10, 1<<15, s.HandleStream).HandlePacket)
	s.Stack.SetTransportProtocolHandler(udp.ProtocolNumber, s.HandlePacket)

	// WithCreatingNIC creates NIC for stack.
	if tcperr := s.Stack.CreateNIC(NICID, NewEndpoint(device, 1500)); tcperr != nil {
		err = fmt.Errorf("fail to create NIC in stack: %s", tcperr)
		return
	}

	// WithPromiscuousMode sets promiscuous mode in the given NIC.
	// In past we did s.AddAddressRange to assign 0.0.0.0/0 onto
	// the interface. We need that to be able to terminate all the
	// incoming connections - to any ip. AddressRange API has been
	// removed and the suggested workaround is to use Promiscuous
	// mode. https://github.com/google/gvisor/issues/3876
	//
	// Ref: https://github.com/majek/slirpnetstack/blob/master/stack.go
	if tcperr := s.Stack.SetPromiscuousMode(NICID, true); tcperr != nil {
		err = fmt.Errorf("set promiscuous mode: %s", tcperr)
		return
	}

	// WithSpoofing sets address spoofing in the given NIC, allowing
	// endpoints to bind to any address in the NIC.
	// Enable spoofing if a stack may send packets from unowned addresses.
	// This change required changes to some netgophers since previously,
	// promiscuous mode was enough to let the netstack respond to all
	// incoming packets regardless of the packet's destination address. Now
	// that a stack.Route is not held for each incoming packet, finding a route
	// may fail with local addresses we don't own but accepted packets for
	// while in promiscuous mode. Since we also want to be able to send from
	// any address (in response the received promiscuous mode packets), we need
	// to enable spoofing.
	//
	// Ref: https://github.com/google/gvisor/commit/8c0701462a84ff77e602f1626aec49479c308127
	if tcperr := s.Stack.SetSpoofing(NICID, true); tcperr != nil {
		err = fmt.Errorf("set spoofing: %s", tcperr)
		return
	}

	s.conns = make(map[string]*UDPConn)
	return
}

func (s *Stack) HandleStream(r *tcp.ForwarderRequest) {
	var id = r.ID()
	var wq = waiter.Queue{}
	ep, tcperr := r.CreateEndpoint(&wq)
	if tcperr != nil {
		s.Error(fmt.Sprintf("tcp %v:%v <---> %v:%v create endpoint error: %v",
			net.IP(id.RemoteAddress),
			int(id.RemotePort),
			net.IP(id.LocalAddress),
			int(id.LocalPort),
			tcperr,
		))
		// prevent potential half-open TCP connection leak.
		r.Complete(true)
		return
	}
	r.Complete(false)

	// set keepalive
	if err := func(ep tcpip.Endpoint) error {
		ep.SocketOptions().SetKeepAlive(true)
		idleOpt := tcpip.KeepaliveIdleOption(60 * time.Second)
		if tcperr := ep.SetSockOpt(&idleOpt); tcperr != nil {
			return fmt.Errorf("set keepalive idle: %s", tcperr)
		}
		intervalOpt := tcpip.KeepaliveIntervalOption(30 * time.Second)
		if tcperr := ep.SetSockOpt(&intervalOpt); tcperr != nil {
			return fmt.Errorf("set keepalive interval: %s", tcperr)
		}
		return nil
	}(ep); err != nil {
		s.Error(fmt.Sprintf("tcp %v:%v <---> %v:%v create endpoint error: %v",
			net.IP(id.RemoteAddress),
			int(id.RemotePort),
			net.IP(id.LocalAddress),
			int(id.LocalPort),
			err,
		))
	}

	go s.Handler.Handle(gonet.NewTCPConn(&wq, ep), &net.TCPAddr{IP: net.IP(id.LocalAddress), Port: int(id.LocalPort)})
}

func (s *Stack) Get(k string) (*UDPConn, bool) {
	s.mutex.Lock()
	conn, ok := s.conns[k]
	s.mutex.Unlock()
	return conn, ok
}

func (s *Stack) Add(k string, conn *UDPConn) {
	s.mutex.Lock()
	s.conns[k] = conn
	s.mutex.Unlock()
}

func (s *Stack) Del(k string) {
	s.mutex.Lock()
	delete(s.conns, k)
	s.mutex.Unlock()
}

func (s *Stack) HandlePacket(id stack.TransportEndpointID, pkt *stack.PacketBuffer) bool {
	// Ref: gVisor pkg/tcpip/transport/udp/endpoint.go HandlePacket
	udpHdr := header.UDP(pkt.TransportHeader().View())
	if int(udpHdr.Length()) > pkt.Data.Size()+header.UDPMinimumSize {
		s.Error(fmt.Sprintf("udp %v:%v <---> %v:%v malformed packet",
			net.IP(id.RemoteAddress),
			int(id.RemotePort),
			net.IP(id.LocalAddress),
			int(id.LocalPort),
		))
		s.Stack.Stats().UDP.MalformedPacketsReceived.Increment()
		return true
	}

	if !verifyChecksum(udpHdr, pkt) {
		s.Error(fmt.Sprintf("udp %v:%v <---> %v:%v checksum error",
			net.IP(id.RemoteAddress),
			int(id.RemotePort),
			net.IP(id.LocalAddress),
			int(id.LocalPort),
		))
		s.Stack.Stats().UDP.ChecksumErrors.Increment()
		return true
	}

	s.Stack.Stats().UDP.PacketsReceived.Increment()

	key := string(id.RemoteAddress) + string([]byte{byte(id.RemotePort >> 8), byte(id.RemotePort)})
	if conn, ok := s.Get(key); ok {
		conn.HandlePacket(pkt.Data.ToView(), &net.UDPAddr{IP: net.IP(id.LocalAddress), Port: int(id.LocalPort)})
		return true
	}

	netHdr := pkt.Network()
	route, tcperr := s.Stack.FindRoute(
		pkt.NICID,
		netHdr.DestinationAddress(),
		netHdr.SourceAddress(),
		pkt.NetworkProtocolNumber,
		false, /* multicastLoop */
	)
	if tcperr != nil {
		s.Error(fmt.Sprintf("udp %v:%v <---> %v:%v find route error: %v",
			net.IP(id.RemoteAddress),
			int(id.RemotePort),
			net.IP(id.LocalAddress),
			int(id.LocalPort),
			tcperr,
		))
		return true
	}
	route.ResolveWith(pkt.SourceLinkAddress())

	conn := NewUDPConn(
		key,
		net.UDPAddr{IP: net.IP(id.LocalAddress), Port: int(id.LocalPort)},
		net.UDPAddr{IP: net.IP(id.RemoteAddress), Port: int(id.RemotePort)},
		s,
		route,
	)
	s.Add(key, conn)
	conn.HandlePacket(pkt.Data.ToView(), conn.LocalAddr().(*net.UDPAddr))

	go s.Handler.HandlePacket(conn, conn.LocalAddr().(*net.UDPAddr))
	return true
}

func (s *Stack) Close() error {
	for _, conn := range s.conns {
		conn.Close()
	}
	s.Stack.Close()
	return nil
}

// UDP Packet
type Packet struct {
	Addr *net.UDPAddr
	Byte []byte
}

// UDPtConn
type UDPConn struct {
	deadlineTimer

	key    string
	route  stack.Route
	stack  *Stack
	addr   net.UDPAddr
	raddr  net.UDPAddr
	closed chan struct{}
	stream chan Packet
}

func NewUDPConn(key string, addr, raddr net.UDPAddr, s *Stack, r stack.Route) *UDPConn {
	conn := &UDPConn{
		key:    key,
		route:  r,
		stack:  s,
		addr:   addr,
		raddr:  raddr,
		closed: make(chan struct{}),
		stream: make(chan Packet, 16),
	}
	conn.deadlineTimer.init()
	return conn
}

func (conn *UDPConn) Close() error {
	select {
	case <-conn.closed:
		return nil
	default:
		close(conn.closed)
	}
	conn.stack.Del(conn.key)
	conn.route.Release()
	return nil
}

func (conn *UDPConn) LocalAddr() net.Addr {
	return &conn.addr
}

func (conn *UDPConn) RemoteAddr() net.Addr {
	return &conn.raddr
}

func (conn *UDPConn) ReadTo(b []byte) (n int, addr net.Addr, err error) {
	deadline := conn.readCancel()
	select {
	case <-deadline:
		err = timeoutError{}
	case <-conn.closed:
		err = io.EOF
	case pkt := <-conn.stream:
		n = copy(b, pkt.Byte)
		addr = pkt.Addr
	}
	return
}

func (conn *UDPConn) WriteFrom(b []byte, addr net.Addr) (int, error) {
	v := buffer.View(b)
	if len(v) > header.UDPMaximumPacketSize {
		return 0, errors.New(tcpip.ErrMessageTooLong.String())
	}

	src, ok := addr.(*net.UDPAddr)
	if !ok {
		return 0, errors.New("addr type error")
	}

	route := conn.route.Clone()
	defer route.Release()

	if ip := src.IP.To4(); ip != nil {
		route.LocalAddress = tcpip.Address(ip)
	} else {
		route.LocalAddress = tcpip.Address(src.IP.To16())
	}

	if tcperr := sendUDP(
		&route,
		v.ToVectorisedView(),
		uint16(src.Port),
		uint16(conn.raddr.Port),
		0,    /* ttl */
		true, /* useDefaultTTL */
		0,    /* tos */
		nil,  /* owner */
		true,
	); tcperr != nil {
		return 0, errors.New(tcperr.String())
	}
	return len(b), nil
}

func (conn *UDPConn) HandlePacket(b []byte, addr *net.UDPAddr) {
	select {
	case <-conn.closed:
	case conn.stream <- Packet{Addr: addr, Byte: b}:
	}
}

// sendUDP sends a UDP segment via the provided network endpoint and under the
// provided identity.
//
// sendUDP gvisor.dev/gvisor/pkg/tcpip/transport/udp.sendUDP
func sendUDP(r *stack.Route, data buffer.VectorisedView, localPort, remotePort uint16, ttl uint8, useDefaultTTL bool, tos uint8, owner tcpip.PacketOwner, noChecksum bool) *tcpip.Error {
	const ProtocolNumber = header.UDPProtocolNumber

	pkt := stack.NewPacketBuffer(stack.PacketBufferOptions{
		ReserveHeaderBytes: header.UDPMinimumSize + int(r.MaxHeaderLength()),
		Data:               data,
	})
	pkt.Owner = owner

	// Initialize the UDP header.
	udp := header.UDP(pkt.TransportHeader().Push(header.UDPMinimumSize))
	pkt.TransportProtocolNumber = ProtocolNumber

	length := uint16(pkt.Size())
	udp.Encode(&header.UDPFields{
		SrcPort: localPort,
		DstPort: remotePort,
		Length:  length,
	})

	// Set the checksum field unless TX checksum offload is enabled.
	// On IPv4, UDP checksum is optional, and a zero value indicates the
	// transmitter skipped the checksum generation (RFC768).
	// On IPv6, UDP checksum is not optional (RFC2460 Section 8.1).
	if r.RequiresTXTransportChecksum() &&
		(!noChecksum || r.NetProto == header.IPv6ProtocolNumber) {
		xsum := r.PseudoHeaderChecksum(ProtocolNumber, length)
		for _, v := range data.Views() {
			xsum = header.Checksum(v, xsum)
		}
		udp.SetChecksum(^udp.CalculateChecksum(xsum))
	}

	if useDefaultTTL {
		ttl = r.DefaultTTL()
	}
	if err := r.WritePacket(nil /* gso */, stack.NetworkHeaderParams{
		Protocol: ProtocolNumber,
		TTL:      ttl,
		TOS:      tos,
	}, pkt); err != nil {
		r.Stats().UDP.PacketSendErrors.Increment()
		return err
	}

	// Track count of packets sent.
	r.Stats().UDP.PacketsSent.Increment()
	return nil
}

// verifyChecksum verifies the checksum unless RX checksum offload is enabled.
// On IPv4, UDP checksum is optional, and a zero value means the transmitter
// omitted the checksum generation (RFC768).
// On IPv6, UDP checksum is not optional (RFC2460 Section 8.1).
//
// verifyChecksum gvisor.dev/gvisor/pkg/tcpip/transport/udp.verifyChecksum
func verifyChecksum(hdr header.UDP, pkt *stack.PacketBuffer) bool {
	const ProtocolNumber = header.UDPProtocolNumber

	if !pkt.RXTransportChecksumValidated &&
		(hdr.Checksum() != 0 || pkt.NetworkProtocolNumber == header.IPv6ProtocolNumber) {
		netHdr := pkt.Network()
		xsum := header.PseudoHeaderChecksum(ProtocolNumber, netHdr.DestinationAddress(), netHdr.SourceAddress(), hdr.Length())
		for _, v := range pkt.Data.Views() {
			xsum = header.Checksum(v, xsum)
		}
		return hdr.CalculateChecksum(xsum) == 0xffff
	}
	return true
}
