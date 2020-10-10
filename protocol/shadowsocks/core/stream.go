package core

import (
	"bytes"
	"crypto/cipher"
	"crypto/rand"
	"errors"
	"io"
	"net"
	"sync"
)

const MaxPacketSize = 16384

var byteBuffer = sync.Pool{New: newBuffer}

func newBuffer() interface{} {
	return make([]byte, 1024+MaxPacketSize)
}

func Get() []byte {
	return byteBuffer.Get().([]byte)
}

func Put(b []byte) {
	byteBuffer.Put(b)
}

type CloseReader interface {
	CloseRead() error
}

type CloseWriter interface {
	CloseWrite() error
}

type Reader struct {
	io.Reader
	cipher.AEAD
	nonce []byte
	buff  []byte
	left  []byte
}

func NewReader(reader io.Reader, ciph Cipher) (r *Reader, err error) {
	r = &Reader{}
	err = r.init(reader, ciph)
	return
}

func (r *Reader) init(reader io.Reader, cipher Cipher) (err error) {
	r.Reader = reader

	salt := make([]byte, cipher.SaltSize())
	if _, err := io.ReadFull(r.Reader, salt); err != nil {
		return err
	}

	r.AEAD, err = cipher.NewAead(salt)
	if err != nil {
		return
	}

	r.nonce = make([]byte, r.AEAD.NonceSize())
	r.buff = Get()
	return
}

func (r *Reader) Close() error {
	Put(r.buff)
	return nil
}

func (r *Reader) read() (int, error) {
	buf := r.buff[:2+r.Overhead()]
	if _, err := io.ReadFull(r.Reader, buf); err != nil {
		return 0, err
	}
	if _, err := r.Open(buf[:0], r.nonce, buf, nil); err != nil {
		return 0, err
	}
	increment(r.nonce)

	buf = r.buff[:(int(buf[0])<<8|int(buf[1]))+r.Overhead()]
	if _, err := io.ReadFull(r.Reader, buf); err != nil {
		return 0, err
	}
	if _, err := r.Open(buf[:0], r.nonce, buf, nil); err != nil {
		return 0, err
	}
	increment(r.nonce)

	return len(buf) - r.Overhead(), nil
}

func (r *Reader) Read(b []byte) (int, error) {
	if len(r.left) > 0 {
		n := copy(b, r.left)
		r.left = r.left[n:]
		return n, nil
	}

	n, err := r.read()
	nr := copy(b, r.buff[:n])
	if nr < n {
		r.left = r.buff[nr:n]
	}

	return nr, err
}

func (r *Reader) WriteTo(w io.Writer) (n int64, err error) {
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
			if nr != nw {
				err = io.ErrShortWrite
				break
			}
		}
		if er != nil {
			if errors.Is(er, io.EOF) {
				break
			}
			err = er
			break
		}
	}

	return n, err
}

type Writer struct {
	io.Writer
	cipher.AEAD
	reader *bytes.Reader
	nonce  []byte
	buff   []byte
	buf    []byte
}

func NewWriter(writer io.Writer, ciph Cipher) (w *Writer, err error) {
	w = &Writer{reader: bytes.NewReader(nil)}
	err = w.init(w, ciph)
	return w, err
}

func (w *Writer) init(writer io.Writer, ciph Cipher) error {
	w.Writer = writer
	salt := make([]byte, ciph.SaltSize())

	_, err := rand.Read(salt)
	if err != nil {
		return err
	}

	w.AEAD, err = ciph.NewAead(salt)
	if err != nil {
		return err
	}

	w.nonce = make([]byte, w.AEAD.NonceSize())
	w.buff = Get()
	w.buf = w.buff[2+w.Overhead() : 2+w.Overhead()+MaxPacketSize]

	_, err = w.Writer.Write(salt)
	return err
}

func (w *Writer) Close() error {
	Put(w.buff)
	return nil
}

func (w *Writer) Write(b []byte) (int, error) {
	w.reader.Reset(b)
	n, err := w.ReadFrom(w.reader)
	return int(n), err
}

func (w *Writer) ReadFrom(r io.Reader) (n int64, err error) {
	for {
		nr, er := r.Read(w.buf)
		if nr > 0 {
			n += int64(nr)

			w.buff[0] = byte(nr>>8)
			w.buff[1] = byte(nr)

			w.Seal(w.buff[:0], w.nonce, w.buff[:2], nil)
			increment(w.nonce)

			w.Seal(w.buf[:0], w.nonce, w.buf[:nr], nil)
			increment(w.nonce)

			if _, ew := w.Writer.Write(w.buff[:2+w.Overhead()+nr+w.Overhead()]); ew != nil {
				err = ew
				break
			}
		}
		if er != nil {
			if errors.Is(er, io.EOF) {
				break
			}
			err = er
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
	c Cipher
	r Reader
	w Writer
}

func NewConn(conn net.Conn, cipher Cipher) net.Conn {
	if _, ok := cipher.(dummy); ok {
		return conn
	}
	return &Conn{Conn: conn, c: cipher, r: Reader{Reader: conn}, w: Writer{Writer: conn}}
}

func (c *Conn) Close() error {
	c.r.Close()
	c.w.Close()
	return c.Conn.Close()
}

func (c *Conn) Read(b []byte) (int, error) {
	if c.r.AEAD == nil {
		if err := c.r.init(c.Conn, c.c); err != nil {
			return 0, err
		}
	}
	return c.r.Read(b)
}

func (c *Conn) WriteTo(w io.Writer) (int64, error) {
	if c.r.AEAD == nil {
		if err := c.r.init(c.Conn, c.c); err != nil {
			return 0, err
		}
	}
	return c.r.WriteTo(w)
}

func (c *Conn) Write(b []byte) (int, error) {
	if c.w.AEAD == nil {
		if err := c.w.init(c.Conn, c.c); err != nil {
			return 0, err
		}
	}
	return c.w.Write(b)
}

func (c *Conn) ReadFrom(r io.Reader) (int64, error) {
	if c.w.AEAD == nil {
		if err := c.w.init(c.Conn, c.c); err != nil {
			return 0, err
		}
	}
	return c.w.ReadFrom(r)
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
