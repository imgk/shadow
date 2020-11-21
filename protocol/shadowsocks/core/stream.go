package core

import (
	"bytes"
	"crypto/cipher"
	"crypto/rand"
	"errors"
	"io"
	"net"
)

const MaxPacketSize = 16384

func increment(b []byte) {
	for i := range b {
		b[i]++
		if b[i] != 0 {
			return
		}
	}
}

type CloseReader interface {
	CloseRead() error
}

type Reader struct {
	Reader io.Reader
	Cipher Cipher
	AEAD   cipher.AEAD

	nonce []byte
	buff  []byte
	left  []byte
}

func NewReader(r io.Reader, cipher Cipher) *Reader {
	return &Reader{
		Reader: r,
		Cipher: cipher,
	}
}

func (r *Reader) init() (err error) {
	salt := make([]byte, r.Cipher.SaltSize())
	if _, err := io.ReadFull(r.Reader, salt); err != nil {
		return err
	}

	r.AEAD, err = r.Cipher.NewAead(salt)
	if err != nil {
		return
	}

	r.nonce = make([]byte, r.AEAD.NonceSize())
	r.buff = make([]byte, MaxPacketSize+r.AEAD.Overhead())
	return
}

func (r *Reader) Close() (err error) {
	if closer, ok := r.Reader.(CloseReader); ok {
		err = closer.CloseRead()
	}
	return nil
}

func (r *Reader) read() (int, error) {
	buf := r.buff[:2+r.AEAD.Overhead()]
	if _, err := io.ReadFull(r.Reader, buf); err != nil {
		return 0, err
	}
	if _, err := r.AEAD.Open(buf[:0], r.nonce, buf, nil); err != nil {
		return 0, err
	}
	increment(r.nonce)

	buf = r.buff[:(int(buf[0])<<8|int(buf[1]))+r.AEAD.Overhead()]
	if _, err := io.ReadFull(r.Reader, buf); err != nil {
		return 0, err
	}
	if _, err := r.AEAD.Open(buf[:0], r.nonce, buf, nil); err != nil {
		return 0, err
	}
	increment(r.nonce)

	return len(buf) - r.AEAD.Overhead(), nil
}

func (r *Reader) Read(b []byte) (int, error) {
	if r.AEAD == nil {
		if err := r.init(); err != nil {
			return 0, err
		}
	}

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
	if r.AEAD == nil {
		if err := r.init(); err != nil {
			return 0, err
		}
	}

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

type CloseWriter interface {
	CloseWrite() error
}

type Writer struct {
	Writer io.Writer
	Cipher Cipher
	AEAD   cipher.AEAD

	reader *bytes.Reader

	nonce   []byte
	buff    []byte
	payload []byte
}

func NewWriter(w io.Writer, cipher Cipher) *Writer {
	return &Writer{
		Writer: w,
		Cipher: cipher,
	}
}

func (w *Writer) init() error {
	salt := make([]byte, w.Cipher.SaltSize())

	_, err := rand.Read(salt)
	if err != nil {
		return err
	}

	w.AEAD, err = w.Cipher.NewAead(salt)
	if err != nil {
		return err
	}

	w.reader = bytes.NewReader(nil)

	w.nonce = make([]byte, w.AEAD.NonceSize())
	w.buff = make([]byte, 2+w.AEAD.Overhead()+MaxPacketSize+w.AEAD.Overhead())
	w.payload = w.buff[2+w.AEAD.Overhead() : 2+w.AEAD.Overhead()+MaxPacketSize]

	_, err = w.Writer.Write(salt)
	return err
}

func (w *Writer) Close() (err error) {
	if closer, ok := w.Writer.(CloseWriter); ok {
		err = closer.CloseWrite()
	}
	return nil
}

func (w *Writer) Write(b []byte) (int, error) {
	if w.AEAD == nil {
		if err := w.init(); err != nil {
			return 0, err
		}
	}

	w.reader.Reset(b)
	n, err := w.readFrom(w.reader)
	return int(n), err
}

func (w *Writer) ReadFrom(r io.Reader) (int64, error) {
	if w.AEAD == nil {
		if err := w.init(); err != nil {
			return 0, err
		}
	}

	return w.readFrom(r)
}

func (w *Writer) readFrom(r io.Reader) (n int64, err error) {
	for {
		nr, er := r.Read(w.payload)
		if nr > 0 {
			n += int64(nr)

			w.buff[0] = byte(nr >> 8)
			w.buff[1] = byte(nr)

			w.AEAD.Seal(w.buff[:0], w.nonce, w.buff[:2], nil)
			increment(w.nonce)

			w.AEAD.Seal(w.payload[:0], w.nonce, w.payload[:nr], nil)
			increment(w.nonce)

			if _, ew := w.Writer.Write(w.buff[:2+w.AEAD.Overhead()+nr+w.AEAD.Overhead()]); ew != nil {
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

type Conn struct {
	net.Conn
	Reader Reader
	Writer Writer
}

func NewConn(conn net.Conn, cipher Cipher) net.Conn {
	if _, ok := cipher.(dummy); ok {
		return conn
	}

	return &Conn{
		Conn: conn,
		Reader: Reader{
			Reader: conn,
			Cipher: cipher,
		},
		Writer: Writer{
			Writer: conn,
			Cipher: cipher,
		},
	}
}

func (c *Conn) Read(b []byte) (int, error)          { return c.Reader.Read(b) }
func (c *Conn) WriteTo(w io.Writer) (int64, error)  { return c.Reader.WriteTo(w) }
func (c *Conn) Write(b []byte) (int, error)         { return c.Writer.Write(b) }
func (c *Conn) ReadFrom(r io.Reader) (int64, error) { return c.Writer.ReadFrom(r) }
func (c *Conn) CloseRead() error                    { return c.Reader.Close() }
func (c *Conn) CloseWrite() error                   { return c.Writer.Close() }

var (
	_ CloseReader = (*Conn)(nil)
	_ CloseWriter = (*Conn)(nil)
	_ net.Conn    = (*Conn)(nil)
)
