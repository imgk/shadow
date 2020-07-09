package shadowsocks

import (
	"crypto/rand"
	"errors"
	"io"
	"net"
)

var ErrShortPacket = errors.New("short packet")
var _zerononce [128]byte

type PacketConn struct {
	net.PacketConn
	Cipher
	rBuff []byte
	wBuff []byte
}

func NewPacketConn(pc net.PacketConn, ciph Cipher) net.PacketConn {
	if ciph == nil {
		return pc
	}

	return &PacketConn{
		PacketConn: pc,
		Cipher:     ciph,
		rBuff:      make([]byte, MaxBufferSize),
		wBuff:      make([]byte, MaxBufferSize),
	}
}

func Unpack(dst, pkt []byte, ciph Cipher) ([]byte, error) {
	saltSize := ciph.SaltSize()
	if len(pkt) < saltSize {
		return nil, ErrShortPacket
	}

	salt := pkt[:saltSize]
	aead, err := ciph.NewAead(salt)
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
	n, addr, err := pc.PacketConn.ReadFrom(pc.rBuff)
	if err != nil {
		return 0, nil, err
	}

	bb, err := Unpack(b, pc.rBuff[:n], pc.Cipher)
	if err != nil {
		return 0, nil, err
	}

	return len(bb), addr, nil
}

func Pack(dst, pkt []byte, ciph Cipher) ([]byte, error) {
	saltSize := ciph.SaltSize()
	salt := dst[:saltSize]
	_, err := rand.Read(salt)
	if err != nil {
		return nil, err
	}

	aead, err := ciph.NewAead(salt)
	if err != nil {
		return nil, err
	}

	if saltSize+len(dst)+aead.Overhead() < len(pkt) {
		return nil, io.ErrShortBuffer
	}

	return aead.Seal(dst[:saltSize], _zerononce[:aead.NonceSize()], pkt, nil), nil
}

func (pc *PacketConn) WriteTo(b []byte, addr net.Addr) (int, error) {
	bb, err := Pack(pc.wBuff, b, pc.Cipher)
	if err != nil {
		return 0, err
	}

	_, err = pc.PacketConn.WriteTo(bb, addr)
	return len(b), err
}
