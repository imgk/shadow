package core

import (
	"errors"
	"io"
	"net"
	"sync"
	"time"

	"golang.org/x/net/ipv4"
	"golang.org/x/net/ipv6"
)

type TCPConnHandler interface {
	Handle(net.Conn, *net.TCPAddr) error
}

type UDPConnHandler interface {
	Connect(UDPConn, *net.UDPAddr) error
	ReceiveTo(UDPConn, []byte, *net.UDPAddr) error
}

var handleTCP TCPConnHandler
var handleUDP UDPConnHandler

func RegisterTCPConnHandler(h TCPConnHandler) {
	handleTCP = h
}

func RegisterUDPConnHandler(h UDPConnHandler) {
	handleUDP = h
}

func RegisterOutputFn(f func([]byte) (int, error)) {
	Write = f
}

var Write func([]byte) (int, error)

type Conn struct{
	TCPHandler
	net.Conn
	src *net.TCPAddr
	dst *net.TCPAddr
}

func (conn *Conn) Read(b []byte) (int, error) {
	return 0, nil
}

func (conn *Conn) Write(b []byte) (int, error) {
	return 0, nil
}

func (conn *Conn) Close() error {
	return nil
}

func (conn *Conn) RemoteAddr() net.Addr {
	return conn.dst
}

func (conn *Conn) LocalAddr() net.Addr {
	return conn.src
}

func (conn *Conn) SetReadDeadline(t time.Time) error {
	return nil
}

func (conn *Conn) SetWriteDeadline(t time.Time) error {
	return nil
}

func (conn *Conn) SetDeadline(t time.Time) error {
	return nil
}

func (conn *Conn) CloseRead() error {
	return nil
}

func (conn *Conn) CloseWrite() error {
	return nil
}

// from tun driver to connection
func (conn *Conn) WriteTo(p *Packet) error {
	return nil
}

// write packet to tun driver
func (conn *Conn) Output(p *Packet) error {
	return nil
}

type UDPConn interface {
	net.PacketConn
	ReceiveTo([]byte, *net.UDPAddr) error
	WriteFrom([]byte, *net.UDPAddr) (int, error)
}

type PacketConn struct {
	UDPHandler
	net.PacketConn
	src *net.UDPAddr
}

func (conn *PacketConn) ReadFrom(b []byte) (int, error) {
	return 0, nil
}

func (conn *PacketConn) WriteTo(b []byte, addr net.Addr) (int, error) {
	return 0, nil
}

func (conn *PacketConn) SetDeadline(t time.Time) error {
	return nil
}

func (conn *PacketConn) SetReadDeadline(t time.Time) error {
	return nil
}

func (conn *PacketConn) SetWriteDeadline(t time.Time) error {
	return nil
}

func(conn *PacketConn) LocalAddr() net.Addr {
	return conn.src
}

func (conn *PacketConn) ReceiveTo(b []byte, addr *net.UDPAddr) error {
	return nil
}

func (conn *PacketConn) WriteFrom(b []byte, addr *net.UDPAddr) (int, error) {
	return 0, nil
}

func (conn *PacketConn) Close() error {
	return nil
}

// from tun driver
func (conn *PacketConn) Write(p *Packet) error {
	return nil
}

// to tun packet
func (conn *PacketConn) Output(p *Packet) error {
	return nil
}

type IPv4Header struct {
	b1  uint8
	TOS uint8
	Length uint16
	ID uint16
	FragOff uint16
	TTL uint8
	Protocol uint8
	Checksum uint16
	SrcAddr [4]uint8
	DstAddr [4]uint8
}

type IPv6Header struct {
	b1 uint8
	b2 uint8
	flowLabel uint16
	Length uint16
	NextHeader uint8
	HopLimite uint8
	SrcAddr [16]uint8
	DstAddr [16]uint8
}

type TCPHeader struct {
	SrcPort [2]uint8
	DstPort [2]uint8
}

type UDPHeader struct {
	src      [2]uint8
	dst      [2]uint8
	len      [2]uint8
	checksum [2]uint8
}

func (h *UDPHeader) SourcePort() uint16 {
	return uint16(h.src[0]) << 8 | uint16(h.src[1])
}

func (h *UDPHeader) SetSourcePort(p uint16) {
	h.src[0], h.src[1] = uint8(p >> 8), uint8(p)
}

type Fragment []byte

type Packet struct {
	*IPv4Header
	*IPv6Header
	*TCPHeader
	*UDPHeader
	Fragments []Fragment
}

var buffer = sync.Pool{
	New: func() interface{} {
		return &Packet{
			Fragments: []Fragment{},
		}
	},
}

func AllocatePacket() *Packet {
	return buffer.Get().(*Packet)
}

func ReleasePacket(p *Packet) {
	p.IPv4Header = nil
	p.IPv6Header = nil
	p.TCPHeader = nil
	p.UDPHeader = nil

	for i := range p.Fragments {
		p.Fragments[i] = nil
	}

	p.Fragments = p.Fragments[:0]
	buffer.Put(p)
}

func (p *Packet) CopyTo(b []byte) (int, error) {
	return 0, nil
}

type TransportHandler interface {
	Write(p *Packet) error
	Output(p *Packet) error
}

type TCPHandler struct {
	NetworkHandler
	conns map[uint16]*Conn
}

// from tun driver
func (h *TCPHandler) Write(p *Packet) error {
	return nil
}

// to tun driver
func (H *TCPHandler) Output(p *Packet) error {
	return nil
}

type UDPHandler struct {
	NetworkHandler
	conns map[uint16]*PacketConn
}

// from tun driver
func (h *UDPHandler) Write(p *Packet) error {
	return nil
}

// to tun driver
func (H *UDPHandler) Output(p *Packet) error {
	return nil
}

type NetworkHandler interface {
	Write(f Fragment) error
	Output(p *Packet) error
	HeaderLength() int
}

type IPv4Handler struct {
	*Stack
	TCPHandler
	UDPHandler
}

// from tun driver
func (h *IPv4Handler) Write(f Fragment) error {
	return nil
}

// to tun driver
func (h *IPv4Handler) Output(p *Packet) error {
	for i := range p.Fragments {
		h.Stack.Output(p.Fragments[i])
	}

	ReleasePacket(p)
	return nil
}

func (h IPv4Handler) HeaderLength() int {
	return ipv4.HeaderLen
}

type IPv6Handler struct {
	*Stack
	TCPHandler
	UDPHandler
}

// from tun driver
func (h *IPv6Handler) Write(f Fragment) error {
	return nil
}

// to tun driver
func (h *IPv6Handler) Output(p *Packet) error {
	for i := range p.Fragments {
		h.Stack.Output(p.Fragments[i])
	}

	ReleasePacket(p)
	return nil
}

func (h *IPv6Handler) HeaderLength() int {
	return ipv6.HeaderLen
}

type LWIPStack interface {
	DialTCP(string, net.Addr, net.Addr) (net.Conn, error)
	DialUDP(string, net.Addr, net.Addr) (net.PacketConn, error)
	io.Writer
	io.Closer
	RestartTimeouts()
}

type Stack struct {
	IPv4Handler
	IPv6Handler
	active chan struct{}
	MTU    int
	frags  sync.Pool
}

var stack *Stack

func NewLWIPStack() LWIPStack {
	InitStack(1500)

	return stack
}

func InitStack(mtu int) {
	stack = &Stack{
		IPv4Handler: IPv4Handler{
			TCPHandler: TCPHandler{},
			UDPHandler: UDPHandler{},
		},
		IPv6Handler: IPv6Handler{
			TCPHandler: TCPHandler{},
			UDPHandler: UDPHandler{},
		},
		MTU: mtu,
	}

	stack.IPv4Handler.Stack = stack
	stack.IPv6Handler.Stack = stack
	stack.frags = sync.Pool{
		New: func() interface{} {
			return make([]byte, stack.MTU)
		},
	}
}

func Writer() io.Writer {
	return stack
}

// from tun driver
func (s *Stack) Write(b []byte) (n int, err error) {
	if s.MTU < len(b) {
		err = errors.New("size is bigger than MTU")
		return
	}

	f := s.AllocateFragment()
	n = copy(f, b)

	switch f[0] >> 4 {
	case ipv4.Version:
		err = s.IPv4Handler.Write(f)
	case ipv6.Version:
		err = s.IPv6Handler.Write(f)
	default:
		err = errors.New("not valid ip version")
		return
	}

	if err != nil {
		select {
		case <-s.active:
			return 0, errors.New("closed netstack")
		default:
		}
	}

	return n, nil
}

// to tun driver
func (s *Stack) Output(f Fragment) (int, error) {
	n, err := Write(f)
	s.ReleaseFragment(f)

	return n, err
}

func (s *Stack) DialTCP(network string, laddr, raddr net.Addr) (net.Conn, error) {
	return nil, nil
}

func (s *Stack) DialUDP(network string, laddr, raddr net.Addr) (net.PacketConn, error) {
	return nil, nil
}

func (s *Stack) Close() error {
	select {
	case <-s.active:
		return nil
	default:
		close(s.active)
	}

	return nil
}

func (s *Stack) RestartTimeouts() {}

func (s *Stack) AllocateFragment() Fragment {
	return s.frags.Get().(Fragment)
}

func (s *Stack) ReleaseFragment(f Fragment) {
	s.frags.Put(f)
} 
