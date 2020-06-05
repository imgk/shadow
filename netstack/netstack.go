package netstack

import (
	"encoding/binary"
	"errors"
	"fmt"
	"io"
	"net"

	"github.com/eycorsican/go-tun2socks/core"

	"github.com/imgk/shadow/utils"
)

type Device interface {
	io.Reader
	io.WriterTo
	io.Writer
	io.ReaderFrom
	io.Closer
}

type Handler interface {
	Handle(net.Conn, net.Addr) error
	HandlePacket(PacketConn) error
}

type PacketConn interface {
	LocalAddr() net.Addr
	WriteFrom([]byte, net.Addr) (int, error)
	WriteTo([]byte, *net.UDPAddr) error
	ReadTo([]byte) (int, net.Addr, error)
	io.Closer
}

type DirectUDPConn struct {
	core.UDPConn
	net.PacketConn
}

func NewDirectUDPConn(conn core.UDPConn, pc net.PacketConn) *DirectUDPConn {
	return &DirectUDPConn{
		UDPConn:    conn,
		PacketConn: pc,
	}
}

func (conn *DirectUDPConn) Close() error {
	e1 := conn.UDPConn.Close()
	e2 := conn.PacketConn.Close()

	if e1 != nil {
		if e2 != nil {
			return fmt.Errorf("%v and %v", e1, e2)
		}
		return e1
	}

	if e2 != nil {
		return e2
	}

	return nil
}

func (conn *DirectUDPConn) WriteFrom(b []byte, addr net.Addr) (int, error) {
	return conn.UDPConn.WriteFrom(b, addr.(*net.UDPAddr))
}

func (conn *DirectUDPConn) WriteTo(b []byte, addr *net.UDPAddr) error {
	_, err := conn.PacketConn.WriteTo(b, addr)
	return err
}

func (conn *DirectUDPConn) ReadTo(b []byte) (int, net.Addr, error) {
	return 0, nil, errors.New("not support")
}

func (conn *DirectUDPConn) LocalAddr() net.Addr {
	return conn.UDPConn.LocalAddr()
}

type UDPConn struct {
	core.UDPConn
	*io.PipeReader
	*io.PipeWriter
	*stack
	active chan struct{}
	addr   chan net.Addr
	target *net.UDPAddr
}

func NewUDPConn(conn core.UDPConn, tgt *net.UDPAddr, s *stack) *UDPConn {
	r, w := io.Pipe()

	return &UDPConn{
		UDPConn:    conn,
		PipeReader: r,
		PipeWriter: w,
		stack:      s,
		active:     make(chan struct{}),
		addr:       make(chan net.Addr, 1),
		target:     tgt,
	}
}

func (conn *UDPConn) LocalAddr() net.Addr {
	return conn.UDPConn.LocalAddr()
}

func (conn *UDPConn) WriteFrom(data []byte, src net.Addr) (int, error) {
	if conn.target != nil {
		return conn.UDPConn.WriteFrom(data, conn.target)
	}

	addr, err := utils.ResolveUDPAddr(src.(utils.Addr))
	if err != nil {
		return 0, fmt.Errorf("resolve udp addr error: %w", err)
	}

	return conn.UDPConn.WriteFrom(data, addr)
}

func (conn *UDPConn) WriteTo(data []byte, target *net.UDPAddr) error {
	if _, err := conn.PipeWriter.Write(data); err != nil {
		select {
		case <-conn.active:
			err = io.EOF
		default:
		}

		return err
	}

	var origin net.Addr
	addr, err := conn.stack.IPToDomainAddrBuffer(target.IP, make([]byte, utils.MaxAddrLen))
	if err != nil {
		origin = target
	} else {
		binary.BigEndian.PutUint16(addr[len(addr)-2:], uint16(target.Port))
		origin = addr
	}

	select {
	case <-conn.active:
		return io.EOF
	case conn.addr <- origin:
		return nil
	}

	return nil
}

func (conn *UDPConn) ReadTo(b []byte) (int, net.Addr, error) {
	n, err := conn.PipeReader.Read(b)
	if err != nil {
		select {
		case <-conn.active:
			err = io.EOF
		default:
		}

		return n, nil, err
	}

	select {
	case <-conn.active:
		return 0, nil, io.EOF
	case addr, ok := <-conn.addr:
		if ok {
			return n, addr, nil
		}
		return n, addr, io.EOF
	}

	return 0, nil, io.EOF
}

func (conn *UDPConn) Close() error {
	select {
	case <-conn.active:
		return nil
	default:
		close(conn.active)
	}

	conn.PipeReader.Close()
	conn.PipeWriter.Close()

	return conn.UDPConn.Close()
}
