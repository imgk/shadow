package shadowsocks

import (
	"crypto/rand"
	"errors"
	"io"
	"net"
	"sync"
)

var ErrShortPacket = errors.New("short packet")
var _zerononce [128]byte

type PacketConn struct {
	sync.Mutex
	net.PacketConn
	Cipher
	buff []byte
}

func NewPacketConn(pc net.PacketConn, ciph Cipher) net.PacketConn {
	if ciph == nil {
		return pc
	}

	return &PacketConn{
		Mutex:      sync.Mutex{},
		PacketConn: pc,
		Cipher:     ciph,
		buff:       make([]byte, MaxPacketSize<<2),
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
	pc.Lock()
	defer pc.Unlock()

	n, addr, err := pc.PacketConn.ReadFrom(pc.buff)
	if err != nil {
		return 0, nil, err
	}

	bb, err := Unpack(b, pc.buff[:n], pc.Cipher)
	if err != nil {
		return 0, nil, err
	}

	return len(bb), addr, nil
}

func Pack(dst, pkt []byte, ciph Cipher) ([]byte, error) {
	saltSize := ciph.SaltSize()
	salt := dst[:ciph.SaltSize()]
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

	return aead.Seal(dst[:ciph.SaltSize()], _zerononce[:aead.NonceSize()], pkt, nil), nil
}

func (pc *PacketConn) WriteTo(b []byte, addr net.Addr) (int, error) {
	pc.Lock()
	defer pc.Unlock()

	bb, err := Pack(pc.buff, b, pc.Cipher)
	if err != nil {
		return 0, err
	}

	_, err = pc.PacketConn.WriteTo(bb, addr)
	return len(b), err
}
