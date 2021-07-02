package core

import (
	"errors"
	"fmt"
	"io"
	"log"
	"net"
	"sync"
	"time"
	"unsafe"

	"golang.org/x/time/rate"

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

// Stack is ...
// pure go netstack provided by gvisor.dev
type Stack struct {
	// Logger is ...
	Logger
	// Device is ...
	// layer 2 device for reading and writing packets
	Device Device
	// Handler is ...
	// handle tcp and udp connections
	Handler Handler
	// Stack is ...
	Stack *stack.Stack

	// UDP Table
	mu    sync.RWMutex
	conns map[int]*UDPConn
}

// Start is to start the stack
func (s *Stack) Start(device Device, handler Handler, logger Logger, mtu int) (err error) {
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

	// set NICID to 1
	const NICID = tcpip.NICID(1)

	// WithDefaultTTL sets the default TTL used by stack.
	{
		opt := tcpip.DefaultTTLOption(64)
		if tcperr := s.Stack.SetNetworkProtocolOption(ipv4.ProtocolNumber, &opt); tcperr != nil {
			err = fmt.Errorf("set ipv4 default TTL: %s", tcperr)
			return
		}
		if tcperr := s.Stack.SetNetworkProtocolOption(ipv6.ProtocolNumber, &opt); tcperr != nil {
			err = fmt.Errorf("set ipv6 default TTL: %s", tcperr)
			return
		}
	}

	// set forwarding
	if tcperr := s.Stack.SetForwardingDefaultAndAllNICs(ipv4.ProtocolNumber, true); tcperr != nil {
		err = fmt.Errorf("set ipv4 forwarding error: %s", tcperr)
		return
	}
	if tcperr := s.Stack.SetForwardingDefaultAndAllNICs(ipv6.ProtocolNumber, true); tcperr != nil {
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
			log.Panic(fmt.Errorf("unable to ParseCIDR(%s): %w", s, err))
		}

		subnet, err := tcpip.NewSubnet(tcpip.Address(ipNet.IP), tcpip.AddressMask(ipNet.Mask))
		if err != nil {
			log.Panic(fmt.Errorf("unable to NewSubnet(%s): %w", ipNet, err))
		}
		return subnet
	}

	// Add default route table for IPv4 and IPv6
	// This will handle all incoming ICMP packets.
	s.Stack.SetRouteTable([]tcpip.Route{
		{
			// Destination: header.IPv4EmptySubnet,
			Destination: mustSubnet("0.0.0.0/0"),
			NIC:         NICID,
		},
		{
			// Destination: header.IPv6EmptySubnet,
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
	if tcperr := s.Stack.CreateNIC(NICID, NewEndpoint(device, mtu)); tcperr != nil {
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

	s.conns = make(map[int]*UDPConn)
	return
}

// HandleStream is to handle incoming TCP connections
func (s *Stack) HandleStream(r *tcp.ForwarderRequest) {
	id := r.ID()
	wq := waiter.Queue{}
	ep, tcperr := r.CreateEndpoint(&wq)
	if tcperr != nil {
		s.Error("tcp %v:%v <---> %v:%v create endpoint error: %v",
			net.IP(id.RemoteAddress),
			int(id.RemotePort),
			net.IP(id.LocalAddress),
			int(id.LocalPort),
			tcperr,
		)
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
		s.Error("tcp %v:%v <---> %v:%v create endpoint error: %v",
			net.IP(id.RemoteAddress),
			int(id.RemotePort),
			net.IP(id.LocalAddress),
			int(id.LocalPort),
			err,
		)
	}

	go s.Handler.Handle((*TCPConn)(unsafe.Pointer(gonet.NewTCPConn(&wq, ep))), &net.TCPAddr{IP: net.IP(id.LocalAddress), Port: int(id.LocalPort)})
}

// Get is to get *UDPConn
func (s *Stack) Get(k int) (*UDPConn, bool) {
	s.mu.RLock()
	conn, ok := s.conns[k]
	s.mu.RUnlock()
	return conn, ok
}

// Add is to add *UDPConn
func (s *Stack) Add(k int, conn *UDPConn) {
	s.mu.Lock()
	s.conns[k] = conn
	s.mu.Unlock()
}

// Del is to delete *UDPConn
func (s *Stack) Del(k int) {
	s.mu.Lock()
	delete(s.conns, k)
	s.mu.Unlock()
}

// HandlePacket is to handle UDP connections
func (s *Stack) HandlePacket(id stack.TransportEndpointID, pkt *stack.PacketBuffer) bool {
	// Ref: gVisor pkg/tcpip/transport/udp/endpoint.go HandlePacket
	udpHdr := header.UDP(pkt.TransportHeader().View())
	if int(udpHdr.Length()) > pkt.Data().Size()+header.UDPMinimumSize {
		s.Error("udp %v:%v <---> %v:%v malformed packet",
			net.IP(id.RemoteAddress),
			int(id.RemotePort),
			net.IP(id.LocalAddress),
			int(id.LocalPort),
		)
		s.Stack.Stats().UDP.MalformedPacketsReceived.Increment()
		return true
	}

	if !verifyChecksum(udpHdr, pkt) {
		s.Error("udp %v:%v <---> %v:%v checksum error",
			net.IP(id.RemoteAddress),
			int(id.RemotePort),
			net.IP(id.LocalAddress),
			int(id.LocalPort),
		)
		s.Stack.Stats().UDP.ChecksumErrors.Increment()
		return true
	}

	s.Stack.Stats().UDP.PacketsReceived.Increment()

	key := int(id.RemotePort)
	if conn, ok := s.Get(key); ok {
		vv := pkt.Data().ExtractVV()
		conn.HandlePacket(vv.ToView(), &net.UDPAddr{IP: net.IP(id.LocalAddress), Port: int(id.LocalPort)})
		return true
	}

	conn := NewUDPConn(key, id, pkt, s)
	s.Add(key, conn)
	vv := pkt.Data().ExtractVV()
	conn.HandlePacket(vv.ToView(), conn.LocalAddr().(*net.UDPAddr))

	go s.Handler.HandlePacket(conn, conn.LocalAddr().(*net.UDPAddr))
	return true
}

// Close is to close the stack
func (s *Stack) Close() error {
	for _, conn := range s.conns {
		conn.Close()
	}
	s.Stack.Close()
	return nil
}

// TCPConn is ...
type TCPConn struct {
	gonet.TCPConn
}

// Packet is ...
type Packet struct {
	// Addr is ...
	// target address
	Addr *net.UDPAddr
	// Byte is ...
	// packet payload
	Byte []byte
}

// UDPConn is ...
type UDPConn struct {
	deadlineTimer

	key   int
	stack *Stack

	routeInfo struct {
		src tcpip.Address
		nic tcpip.NICID
		pn  tcpip.NetworkProtocolNumber
		id  stack.TransportEndpointID
	}

	stream chan Packet
	closed chan struct{}
}

// NewUDPConn is to create a new *UDPConn
func NewUDPConn(key int, id stack.TransportEndpointID, pkt *stack.PacketBuffer, s *Stack) *UDPConn {
	conn := &UDPConn{
		key:    key,
		stack:  s,
		stream: make(chan Packet, 16),
		closed: make(chan struct{}),
	}
	hdr := pkt.Network()
	conn.routeInfo.src = hdr.SourceAddress()
	conn.routeInfo.nic = pkt.NICID
	conn.routeInfo.pn = pkt.NetworkProtocolNumber
	conn.routeInfo.id = id

	conn.deadlineTimer.init()
	return conn
}

// Close close UDPConn
func (conn *UDPConn) Close() error {
	select {
	case <-conn.closed:
		return nil
	default:
		close(conn.closed)
	}
	conn.stack.Del(conn.key)
	return nil
}

// LocalAddr is net.PacketConn.LocalAddr
func (conn *UDPConn) LocalAddr() net.Addr {
	return &net.UDPAddr{IP: net.IP(conn.routeInfo.id.LocalAddress), Port: int(conn.routeInfo.id.LocalPort)}
}

// RemoteAddr is net.PacketConn.RemoteAddr
func (conn *UDPConn) RemoteAddr() net.Addr {
	return &net.UDPAddr{IP: net.IP(conn.routeInfo.id.RemoteAddress), Port: int(conn.routeInfo.id.RemotePort)}
}

// ReadTo is ...
func (conn *UDPConn) ReadTo(b []byte) (n int, addr net.Addr, err error) {
	deadline := conn.readCancel()
	select {
	case <-deadline:
		err = (*timeoutError)(nil)
	case <-conn.closed:
		err = io.EOF
	case pkt := <-conn.stream:
		n = copy(b, pkt.Byte)
		addr = pkt.Addr
	}
	return
}

// WriteFrom is ...
func (conn *UDPConn) WriteFrom(b []byte, addr net.Addr) (int, error) {
	v := buffer.View(b)
	if len(v) > header.UDPMaximumPacketSize {
		return 0, errors.New((&tcpip.ErrMessageTooLong{}).String())
	}

	src, ok := addr.(*net.UDPAddr)
	if !ok {
		return 0, errors.New("core.UDPConn.WriteFrom error: addr type error")
	}

	route, tcperr := conn.stack.Stack.FindRoute(conn.routeInfo.nic, tcpip.Address(src.IP), conn.routeInfo.src, conn.routeInfo.pn, false)
	if tcperr != nil {
		return 0, errors.New(tcperr.String())
	}
	defer route.Release()

	n, tcperr := (&udpPacketInfo{
		route:         route,
		data:          v,
		localPort:     uint16(src.Port),
		remotePort:    conn.routeInfo.id.RemotePort,
		ttl:           0,    /* ttl */
		useDefaultTTL: true, /* useDefaultTTL */
		tos:           0,    /* tos */
		owner:         nil,  /* owner */
		noChecksum:    true,
	}).send()
	if tcperr != nil {
		return n, errors.New(tcperr.String())
	}
	return n, nil
}

// HandlePacket is to read packet to UDPConn
func (conn *UDPConn) HandlePacket(b []byte, addr *net.UDPAddr) {
	select {
	case <-conn.closed:
	case conn.stream <- Packet{Addr: addr, Byte: b}:
	}
}

// use unsafe package
var _ unsafe.Pointer = unsafe.Pointer(nil)

// udpPacketInfo contains all information required to send a UDP packet.
//
// This should be used as a value-only type, which exists in order to simplify
// return value syntax. It should not be exported or extended.
type udpPacketInfo struct {
	route         *stack.Route
	data          buffer.View
	localPort     uint16
	remotePort    uint16
	ttl           uint8
	useDefaultTTL bool
	tos           uint8
	owner         tcpip.PacketOwner
	noChecksum    bool
}

// send sends the given packet.
func (u *udpPacketInfo) send() (int, tcpip.Error) {
	const ProtocolNumber = header.UDPProtocolNumber

	vv := u.data.ToVectorisedView()
	pkt := stack.NewPacketBuffer(stack.PacketBufferOptions{
		ReserveHeaderBytes: header.UDPMinimumSize + int(u.route.MaxHeaderLength()),
		Data:               vv,
	})
	pkt.Owner = u.owner

	// Initialize the UDP header.
	udp := header.UDP(pkt.TransportHeader().Push(header.UDPMinimumSize))
	pkt.TransportProtocolNumber = ProtocolNumber

	length := uint16(pkt.Size())
	udp.Encode(&header.UDPFields{
		SrcPort: u.localPort,
		DstPort: u.remotePort,
		Length:  length,
	})

	// Set the checksum field unless TX checksum offload is enabled.
	// On IPv4, UDP checksum is optional, and a zero value indicates the
	// transmitter skipped the checksum generation (RFC768).
	// On IPv6, UDP checksum is not optional (RFC2460 Section 8.1).
	if u.route.RequiresTXTransportChecksum() &&
		(!u.noChecksum || u.route.NetProto() == header.IPv6ProtocolNumber) {
		xsum := u.route.PseudoHeaderChecksum(ProtocolNumber, length)
		for _, v := range vv.Views() {
			xsum = header.Checksum(v, xsum)
		}
		udp.SetChecksum(^udp.CalculateChecksum(xsum))
	}

	if u.useDefaultTTL {
		u.ttl = u.route.DefaultTTL()
	}
	if err := u.route.WritePacket(stack.NetworkHeaderParams{
		Protocol: ProtocolNumber,
		TTL:      u.ttl,
		TOS:      u.tos,
	}, pkt); err != nil {
		u.route.Stats().UDP.PacketSendErrors.Increment()
		return 0, err
	}

	// Track count of packets sent.
	u.route.Stats().UDP.PacketsSent.Increment()
	return len(u.data), nil
}

// verifyChecksum verifies the checksum unless RX checksum offload is enabled.
// On IPv4, UDP checksum is optional, and a zero value means the transmitter
// omitted the checksum generation (RFC768).
// On IPv6, UDP checksum is not optional (RFC2460 Section 8.1).
//
//go:linkname verifyChecksum gvisor.dev/gvisor/pkg/tcpip/transport/udp.verifyChecksum
func verifyChecksum(hdr header.UDP, pkt *stack.PacketBuffer) bool
