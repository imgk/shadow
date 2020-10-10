package core

import (
	"crypto/rand"
	"errors"
	"io"
	"net"
)

var ErrShortPacket = errors.New("short packet")
var _zerononce = [128]byte{}

type PacketConn struct {
	net.PacketConn
	c Cipher
}

func NewPacketConn(pc net.PacketConn, ciph Cipher) net.PacketConn {
	if _, ok := ciph.(dummy); ok {
		return pc
	}
	return &PacketConn{PacketConn: pc, c: ciph}
}

func Unpack(dst, pkt []byte, cipher Cipher) ([]byte, error) {
	saltSize := cipher.SaltSize()
	if len(pkt) < saltSize {
		return nil, ErrShortPacket
	}

	salt := pkt[:saltSize]
	aead, err := cipher.NewAead(salt)
	if err != nil {
		return nil, err
	}

	if len(pkt) < saltSize+aead.Overhead() {
		return nil, ErrShortPacket
	}
	if saltSize+len(dst)+aead.Overhead() < len(pkt) {
		return nil, io.ErrShortBuffer
	}

	return aead.Open(dst[:0], _zerononce[:aead.NonceSize()], pkt[saltSize:], nil)
}

func (pc *PacketConn) ReadFrom(b []byte) (int, net.Addr, error) {
	buff := Get()
	defer Put(buff)

	n, addr, err := pc.PacketConn.ReadFrom(buff)
	if err != nil {
		return 0, nil, err
	}

	bb, err := Unpack(b, buff[:n], pc.c)
	if err != nil {
		return 0, nil, err
	}

	return len(bb), addr, nil
}

func Pack(dst, pkt []byte, cipher Cipher) ([]byte, error) {
	saltSize := cipher.SaltSize()
	salt := dst[:saltSize]
	_, err := rand.Read(salt)
	if err != nil {
		return nil, err
	}

	aead, err := cipher.NewAead(salt)
	if err != nil {
		return nil, err
	}

	if saltSize+len(dst)+aead.Overhead() < len(pkt) {
		return nil, io.ErrShortBuffer
	}

	return aead.Seal(dst[:saltSize], _zerononce[:aead.NonceSize()], pkt, nil), nil
}

func (pc *PacketConn) WriteTo(b []byte, addr net.Addr) (int, error) {
	buff := Get()
	defer Put(buff)

	bb, err := Pack(buff, b, pc.c)
	if err != nil {
		return 0, err
	}

	_, err = pc.PacketConn.WriteTo(bb, addr)
	return len(b), err
}
