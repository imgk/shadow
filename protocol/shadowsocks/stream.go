package shadowsocks

import (
	"bytes"
	"crypto/cipher"
	"crypto/rand"
	"encoding/binary"
	"io"
	"net"
)

const MaxPacketSize = 16384

type reader struct {
	io.Reader
	cipher.AEAD
	nonce []byte
	buff  []byte
	left  []byte
}

func newReader(c net.Conn, aead cipher.AEAD) *reader {
	return &reader{
		Reader: c,
		AEAD:   aead,
		nonce:  make([]byte, aead.NonceSize()),
		buff:   make([]byte, MaxPacketSize+aead.Overhead()),
	}
}

func (r *reader) read() (int, error) {
	buf := r.buff[:2+r.Overhead()]
	_, err := io.ReadFull(r.Reader, buf)
	if err != nil {
		return 0, err
	}
	_, err = r.Open(buf[:0], r.nonce, buf, nil)
	if err != nil {
		return 0, err
	}
	increment(r.nonce)

	buf = r.buff[:int(binary.BigEndian.Uint16(buf[0:]))+r.Overhead()]
	n, err := io.ReadFull(r.Reader, buf)
	if err != nil {
		return 0, err
	}
	_, err = r.Open(buf[:0], r.nonce, buf, nil)
	if err != nil {
		return 0, err
	}
	increment(r.nonce)

	return n - r.Overhead(), nil
}

func (r *reader) Read(b []byte) (int, error) {
	if len(r.left) > 0 {
		n := copy(b, r.left)
		r.left = r.left[n:]
		return n, nil
	}

	n, err := r.read()
	m := copy(b, r.buff[:n])
	if m < n {
		r.left = r.buff[m:n]
	}

	return m, err
}

func (r *reader) WriteTo(w io.Writer) (n int64, err error) {
	for len(r.left) > 0 {
		nw, ew := w.Write(r.left)
		r.left = r.left[nw:]
		n += int64(nw)
		if ew != nil {
			return n, ew
		}
	}

	for {
		nr, er := r.read()
		if nr > 0 {
			nw, ew := w.Write(r.buff[:nr])
			n += int64(nw)

			if ew != nil {
				err = ew
				break
			}
		}

		if er != nil {
			if er != io.EOF {
				err = er
			}
			break
		}
	}

	return n, err
}

type writer struct {
	io.Writer
	cipher.AEAD
	*bytes.Reader
	nonce []byte
	buff  []byte
}

func newWriter(c net.Conn, aead cipher.AEAD) *writer {
	return &writer{
		Writer: c,
		AEAD:   aead,
		Reader: bytes.NewReader(nil),
		nonce:  make([]byte, aead.NonceSize()),
		buff:   make([]byte, 2+aead.Overhead()+MaxPacketSize+aead.Overhead()),
	}
}

func (w *writer) Write(b []byte) (int, error) {
	w.Reader.Reset(b)
	n, err := w.ReadFrom(w.Reader)
	return int(n), err
}

func (w *writer) ReadFrom(r io.Reader) (n int64, err error) {
	buf := w.buff[2+w.Overhead() : 2+w.Overhead()+MaxPacketSize]
	for {
		nr, er := r.Read(buf)
		if nr > 0 {
			n += int64(nr)
			binary.BigEndian.PutUint16(w.buff[0:], uint16(nr))

			w.Seal(w.buff[:0], w.nonce, w.buff[:2], nil)
			increment(w.nonce)

			w.Seal(buf[:0], w.nonce, buf[:nr], nil)
			increment(w.nonce)

			_, ew := w.Writer.Write(w.buff[:2+w.Overhead()+nr+w.Overhead()])
			if ew != nil {
				err = ew
				break
			}
		}

		if er != nil {
			if er != io.EOF {
				err = er
			}
			break
		}
	}

	return n, err
}

func increment(b []byte) {
	for i := range b {
		b[i]++
		if b[i] != 0 {
			return
		}
	}
}

type Conn struct {
	net.Conn
	Cipher
	r *reader
	w *writer
}

func NewConn(conn net.Conn, ciph Cipher) net.Conn {
	if ciph == nil {
		return conn
	}

	return &Conn{Conn: conn, Cipher: ciph}
}

func (c *Conn) initReader() error {
	salt := make([]byte, c.SaltSize())
	_, err := io.ReadFull(c.Conn, salt)
	if err != nil {
		return err
	}

	aead, err := c.NewAead(salt)
	if err != nil {
		return err
	}

	c.r = newReader(c.Conn, aead)
	return nil
}

func (c *Conn) initWriter() error {
	salt := make([]byte, c.SaltSize())
	_, err := rand.Read(salt)
	if err != nil {
		return err
	}

	aead, err := c.NewAead(salt)
	if err != nil {
		return err
	}

	_, err = c.Conn.Write(salt)
	if err != nil {
		return err
	}

	c.w = newWriter(c.Conn, aead)
	return nil
}

func (c *Conn) Read(b []byte) (int, error) {
	if c.r == nil {
		if err := c.initReader(); err != nil {
			return 0, err
		}
	}

	return c.r.Read(b)
}

func (c *Conn) WriteTo(w io.Writer) (int64, error) {
	if c.r == nil {
		if err := c.initReader(); err != nil {
			return 0, err
		}
	}

	return c.r.WriteTo(w)
}

func (c *Conn) Write(b []byte) (int, error) {
	if c.w == nil {
		if err := c.initWriter(); err != nil {
			return 0, err
		}
	}

	return c.w.Write(b)
}

func (c *Conn) ReadFrom(r io.Reader) (int64, error) {
	if c.w == nil {
		if err := c.initWriter(); err != nil {
			return 0, err
		}
	}

	return c.w.ReadFrom(r)
}

type CloseReader interface {
	CloseRead() error
}

type CloseWriter interface {
	CloseWrite() error
}

func (c *Conn) CloseRead() error {
	if close, ok := c.Conn.(CloseReader); ok {
		return close.CloseRead()
	}

	return c.Conn.Close()
}

func (c *Conn) CloseWrite() error {
	if close, ok := c.Conn.(CloseWriter); ok {
		return close.CloseWrite()
	}

	return c.Conn.Close()
}
