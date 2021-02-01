package core

import (
	"crypto/rand"
	"errors"
	"io"
	"net"
	"sync"
)

var zerononce = [128]byte{}

// ErrShortPacket is ...
var ErrShortPacket = errors.New("short packet")

// Pool is ...
var Pool = sync.Pool{
	New: func() interface{} {
		b := make([]byte, MaxPacketSize)
		// Return a *[]byte instead of []byte ensures that
		// the []byte is not copied, which would cause a heap
		// allocation on every call to sync.pool.Pool.Put
		return &b
	},
}

// Get is ...
func Get() (lazySlice, []byte) {
	p := Pool.Get().(*[]byte)
	return lazySlice{Pointer: p}, *p
}

// Put is ...
func Put(s lazySlice) {
	Pool.Put(s.Pointer)
}

type lazySlice struct {
	Pointer *[]byte
}

// PacketConn is ...
type PacketConn struct {
	net.PacketConn
	Cipher *Cipher
}

// NewPacketConn is ...
func NewPacketConn(pc net.PacketConn, cipher *Cipher) net.PacketConn {
	if cipher.NewAEAD == nil {
		return pc
	}
	return &PacketConn{PacketConn: pc, Cipher: cipher}
}

// Unpack is ...
func Unpack(dst, pkt []byte, cipher *Cipher) ([]byte, error) {
	saltSize := cipher.SaltSize
	if len(pkt) < saltSize {
		return nil, ErrShortPacket
	}

	salt := pkt[:saltSize]
	aead, err := cipher.NewAEAD(salt)
	if err != nil {
		return nil, err
	}

	if len(pkt) < saltSize+aead.Overhead() {
		return nil, ErrShortPacket
	}
	if saltSize+len(dst)+aead.Overhead() < len(pkt) {
		return nil, io.ErrShortBuffer
	}

	return aead.Open(dst[:0], zerononce[:aead.NonceSize()], pkt[saltSize:], nil)
}

// ReadFrom is ...
func (pc *PacketConn) ReadFrom(b []byte) (int, net.Addr, error) {
	sc, buff := Get()
	defer Put(sc)

	n, addr, err := pc.PacketConn.ReadFrom(buff)
	if err != nil {
		return 0, nil, err
	}

	bb, err := Unpack(b, buff[:n], pc.Cipher)
	if err != nil {
		return 0, nil, err
	}

	return len(bb), addr, nil
}

// Pack is ...
func Pack(dst, pkt []byte, cipher *Cipher) ([]byte, error) {
	saltSize := cipher.SaltSize
	salt := dst[:saltSize]
	_, err := rand.Read(salt)
	if err != nil {
		return nil, err
	}

	aead, err := cipher.NewAEAD(salt)
	if err != nil {
		return nil, err
	}

	if len(dst) < saltSize+len(pkt)+aead.Overhead() {
		return nil, io.ErrShortBuffer
	}

	return aead.Seal(dst[:saltSize], zerononce[:aead.NonceSize()], pkt, nil), nil
}

// WriteTo is ...
func (pc *PacketConn) WriteTo(b []byte, addr net.Addr) (int, error) {
	sc, buff := Get()
	defer Put(sc)

	bb, err := Pack(buff, b, pc.Cipher)
	if err != nil {
		return 0, err
	}

	_, err = pc.PacketConn.WriteTo(bb, addr)
	return len(b), err
}

var _ net.PacketConn = (*PacketConn)(nil)
