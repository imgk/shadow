package utils

import (
	"io"
	"net"
)

type PacketConn interface {
	LocalAddr() net.Addr
	WriteFrom([]byte, net.Addr) (int, error)
	WriteTo([]byte, *net.UDPAddr) error
	ReadTo([]byte) (int, net.Addr, error)
	io.Closer
}
