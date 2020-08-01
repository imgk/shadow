package core

import (
	"fmt"
	"io"
	"net"
	"sync"
	"time"

	"github.com/eycorsican/go-tun2socks/core"
	"go.uber.org/zap"
	"go.uber.org/zap/zapcore"
)

type Device interface {
	io.Closer
	io.Writer
	io.WriterTo
}

type Handler interface {
	Handle(Conn, *net.TCPAddr)
	HandlePacket(PacketConn, *net.UDPAddr)
}

type Conn interface {
	Close() error
	CloseRead() error
	CloseWrite() error
	LocalAddr() net.Addr
	RemoteAddr() net.Addr
	SetDeadline(time.Time) error
	SetReadDeadline(time.Time) error
	SetWriteDeadline(time.Time) error
	Read([]byte) (int, error)
	Write([]byte) (int, error)
}

type PacketConn interface {
	Close() error
	LocalAddr() net.Addr
	RemoteAddr() net.Addr
	SetDeadline(time.Time) error
	SetReadDeadline(time.Time) error
	SetWriteDeadline(time.Time) error
	ReadTo([]byte) (int, net.Addr, error)
	WriteFrom([]byte, net.Addr) (int, error)
}

type Stack struct {
	*zap.Logger
	Device  Device
	Handler Handler
	Stack   core.LWIPStack

	mutex sync.Mutex
	conns map[core.UDPConn]*UDPConn
}

type writerSyncer struct { io.Writer }

func (w writerSyncer) Sync() error { return nil }

func newWriterSyncer(w io.Writer) zapcore.WriteSyncer {
	if wt, ok := w.(zapcore.WriteSyncer); ok {
		return wt
	}
	return writerSyncer{Writer: w}
}

func (s *Stack) Init(device Device, handler Handler, w io.Writer) {
	conf := zapcore.NewConsoleEncoder(zap.NewDevelopmentEncoderConfig())
	zcore := zapcore.NewCore(conf, newWriterSyncer(w), zap.NewAtomicLevelAt(zap.InfoLevel))
	s.Logger = zap.New(zcore, zap.Development())

	s.Device = device
	s.Handler = handler
	s.Stack = core.NewLWIPStack()
	s.conns = make(map[core.UDPConn]*UDPConn)

	core.RegisterOutputFn(device.Write)
	core.RegisterTCPConnHandler(s)
	core.RegisterUDPConnHandler(s)

	go s.ReadFrom(device)
}

func (s *Stack) ReadFrom(rt io.WriterTo) {
	if _, err := rt.WriteTo(s.Stack); err != nil {
		s.Error(fmt.Sprintf("netstack exit error: %v", err))
	}
}

func (s *Stack) Close() error {
	s.Device.Close()
	s.Logger.Sync()
	return s.Stack.Close()
}

func (s *Stack) Handle(conn net.Conn, target *net.TCPAddr) error {
	go s.Handler.Handle(TCPConn{TCPConn: conn.(core.TCPConn)}, target)
	return nil
}

func (s *Stack) Get(k core.UDPConn) (*UDPConn, bool) {
	s.mutex.Lock()
	conn, ok := s.conns[k]
	s.mutex.Unlock()
	return conn, ok
}

func (s *Stack) Add(k core.UDPConn, conn *UDPConn) {
	s.mutex.Lock()
	s.conns[k] = conn
	s.mutex.Unlock()
}

func (s *Stack) Del(k core.UDPConn) {
	s.mutex.Lock()
	delete(s.conns, k)
	s.mutex.Unlock()
}

func (s *Stack) Connect(conn core.UDPConn, target *net.UDPAddr) error {
	pc := NewUDPConn(conn, target, s)
	s.Add(conn, pc)
	go s.Handler.HandlePacket(pc, target)
	return nil
}

func (s *Stack) ReceiveTo(conn core.UDPConn, data []byte, target *net.UDPAddr) error {
	pc, ok := s.Get(conn)
	if ok {
		pc.HandlePacket(data, target)
		return nil
	}
	return nil
}

// timeoutError is how the net package reports timeouts.
type timeoutError struct{}

func (e timeoutError) Error() string   { return "i/o timeout" }
func (e timeoutError) Timeout() bool   { return true }
func (e timeoutError) Temporary() bool { return true }

type deadlineTimer struct {
	// mu protects the fields below.
	mu sync.Mutex

	readTimer     *time.Timer
	readCancelCh  chan struct{}
	writeTimer    *time.Timer
	writeCancelCh chan struct{}
}

func (d *deadlineTimer) init() {
	d.readCancelCh = make(chan struct{})
	d.writeCancelCh = make(chan struct{})
}

func (d *deadlineTimer) readCancel() <-chan struct{} {
	d.mu.Lock()
	c := d.readCancelCh
	d.mu.Unlock()
	return c
}
func (d *deadlineTimer) writeCancel() <-chan struct{} {
	d.mu.Lock()
	c := d.writeCancelCh
	d.mu.Unlock()
	return c
}

// setDeadline contains the shared logic for setting a deadline.
//
// cancelCh and timer must be pointers to deadlineTimer.readCancelCh and
// deadlineTimer.readTimer or deadlineTimer.writeCancelCh and
// deadlineTimer.writeTimer.
//
// setDeadline must only be called while holding d.mu.
func (d *deadlineTimer) setDeadline(cancelCh *chan struct{}, timer **time.Timer, t time.Time) {
	if *timer != nil && !(*timer).Stop() {
		*cancelCh = make(chan struct{})
	}

	// Create a new channel if we already closed it due to setting an already
	// expired time. We won't race with the timer because we already handled
	// that above.
	select {
	case <-*cancelCh:
		*cancelCh = make(chan struct{})
	default:
	}

	// "A zero value for t means I/O operations will not time out."
	// - net.Conn.SetDeadline
	if t.IsZero() {
		return
	}

	timeout := t.Sub(time.Now())
	if timeout <= 0 {
		close(*cancelCh)
		return
	}

	// Timer.Stop returns whether or not the AfterFunc has started, but
	// does not indicate whether or not it has completed. Make a copy of
	// the cancel channel to prevent this code from racing with the next
	// call of setDeadline replacing *cancelCh.
	ch := *cancelCh
	*timer = time.AfterFunc(timeout, func() {
		close(ch)
	})
}

// SetReadDeadline implements net.Conn.SetReadDeadline and
// net.PacketConn.SetReadDeadline.
func (d *deadlineTimer) SetReadDeadline(t time.Time) error {
	d.mu.Lock()
	d.setDeadline(&d.readCancelCh, &d.readTimer, t)
	d.mu.Unlock()
	return nil
}

// SetWriteDeadline implements net.Conn.SetWriteDeadline and
// net.PacketConn.SetWriteDeadline.
func (d *deadlineTimer) SetWriteDeadline(t time.Time) error {
	d.mu.Lock()
	d.setDeadline(&d.writeCancelCh, &d.writeTimer, t)
	d.mu.Unlock()
	return nil
}

// SetDeadline implements net.Conn.SetDeadline and net.PacketConn.SetDeadline.
func (d *deadlineTimer) SetDeadline(t time.Time) error {
	d.mu.Lock()
	d.setDeadline(&d.readCancelCh, &d.readTimer, t)
	d.setDeadline(&d.writeCancelCh, &d.writeTimer, t)
	d.mu.Unlock()
	return nil
}

// TCPConn
type TCPConn struct {
	core.TCPConn
}

func (conn TCPConn) RemoteAddr() net.Addr {
	return conn.TCPConn.LocalAddr()
}

func (conn TCPConn) LocalAddr() net.Addr {
	return conn.TCPConn.RemoteAddr()
}

// UDPConn
type Packet struct {
	Addr *net.UDPAddr
	Byte []byte
}

type UDPConn struct {
	deadlineTimer

	core.UDPConn
	stack  *Stack
	addr   *net.UDPAddr
	closed chan struct{}
	stream chan Packet
	read   chan struct{}
}

func NewUDPConn(c core.UDPConn, addr *net.UDPAddr, stack *Stack) *UDPConn {
	conn := &UDPConn{
		UDPConn: c,
		stack:   stack,
		addr:    addr,
		closed:  make(chan struct{}),
		stream:  make(chan Packet),
		read:    make(chan struct{}),
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

	conn.stack.Del(conn.UDPConn)
	return conn.UDPConn.Close()
}

func (conn *UDPConn) LocalAddr() net.Addr {
	return conn.addr
}

func (conn *UDPConn) RemoteAddr() net.Addr {
	return conn.UDPConn.LocalAddr()
}

func (conn *UDPConn) ReadTo(b []byte) (n int, addr net.Addr, err error) {
	deadline := conn.readCancel()
	select {
	case <-deadline:
		err = timeoutError{}
	case <-conn.closed:
		err = io.EOF
	case packet := <-conn.stream:
		n = copy(b, packet.Byte)
		addr = packet.Addr
		conn.read <- struct{}{}
	}

	return
}

func (conn *UDPConn) WriteFrom(b []byte, addr net.Addr) (int, error) {
	return conn.UDPConn.WriteFrom(b, addr.(*net.UDPAddr))
}

func (conn *UDPConn) HandlePacket(b []byte, addr *net.UDPAddr) {
	select {
	case <-conn.closed:
	case conn.stream <- Packet{Addr: addr, Byte: b}:
		<-conn.read
	}
}
