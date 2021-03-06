package core

import (
	"bytes"
	"crypto/cipher"
	"crypto/rand"
	"errors"
	"fmt"
	"io"
	"net"
	"time"
)

// MaxPacketSize is ...
// the maximum size of payload
const MaxPacketSize = 0x3FFF // 16k - 1

func increment(b []byte) {
	for i := range b {
		b[i]++
		if b[i] != 0 {
			return
		}
	}
}

// CloseReader is ...
type CloseReader interface {
	CloseRead() error
}

// Reader is ...
type Reader struct {
	// Reader is ...
	Reader io.ReadCloser
	// Cipher is ...
	Cipher *Cipher
	// AEAD is ...
	AEAD cipher.AEAD

	nonce []byte
	buff  []byte
	left  []byte
}

// NewReader is ...
func NewReader(r io.ReadCloser, cipher *Cipher) *Reader {
	reader := &Reader{Reader: r, Cipher: cipher}
	return reader
}

func (r *Reader) init() (err error) {
	salt := make([]byte, r.Cipher.SaltSize)
	if _, err := io.ReadFull(r.Reader, salt); err != nil {
		return fmt.Errorf("init Reader error: %v", err)
	}

	r.AEAD, err = r.Cipher.NewAEAD(salt)
	if err != nil {
		return
	}

	r.nonce = make([]byte, r.AEAD.NonceSize())
	r.buff = make([]byte, MaxPacketSize+r.AEAD.Overhead())
	return
}

// CloseRead is ...
func (r *Reader) CloseRead() error {
	if closer, ok := r.Reader.(CloseReader); ok {
		return closer.CloseRead()
	}
	return errors.New("not supported")
}

// Close is ...
func (r *Reader) Close() error {
	return r.Reader.Close()
}

// read one packet
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

// Read is ...
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

// WriteTo is ...
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

// CloseWriter is ...
type CloseWriter interface {
	CloseWrite() error
}

// Writer is ...
type Writer struct {
	// Writer is ...
	Writer io.WriteCloser
	// Cipehr is ...
	Cipher *Cipher
	// AEAD is ...
	AEAD cipher.AEAD

	nonce   []byte
	buff    []byte
	payload []byte
}

// NewWriter is ...
func NewWriter(w io.WriteCloser, cipher *Cipher) *Writer {
	writer := &Writer{Writer: w, Cipher: cipher}
	return writer
}

func (w *Writer) init() error {
	salt := make([]byte, w.Cipher.SaltSize)

	_, err := rand.Read(salt)
	if err != nil {
		return err
	}

	w.AEAD, err = w.Cipher.NewAEAD(salt)
	if err != nil {
		return err
	}

	w.nonce = make([]byte, w.AEAD.NonceSize())
	w.buff = make([]byte, 2+w.AEAD.Overhead()+MaxPacketSize+w.AEAD.Overhead())
	w.payload = w.buff[2+w.AEAD.Overhead() : 2+w.AEAD.Overhead()+MaxPacketSize]

	_, err = w.Writer.Write(salt)
	return err
}

// CloseWrite is ...
func (w *Writer) CloseWrite() error {
	if closer, ok := w.Writer.(CloseWriter); ok {
		return closer.CloseWrite()
	}
	return errors.New("not supported")
}

// Close is ...
func (w *Writer) Close() error {
	return w.Writer.Close()
}

// Write is ...
func (w *Writer) Write(b []byte) (int, error) {
	if w.AEAD == nil {
		if err := w.init(); err != nil {
			return 0, err
		}
	}

	n, err := w.readFrom(bytes.NewReader(b))
	return int(n), err
}

// ReadFrom is ...
func (w *Writer) ReadFrom(r io.Reader) (int64, error) {
	if w.AEAD == nil {
		if err := w.init(); err != nil {
			return 0, err
		}
	}

	return w.readFrom(r)
}

// readFrom all bytes
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

// Conn is ...
type Conn struct {
	// nc is ...
	nc net.Conn
	// Reader is ...
	Reader
	// Writer is ...
	Writer
}

// NewConn is ...
func NewConn(conn net.Conn, cipher *Cipher) net.Conn {
	if cipher.NewAEAD == nil {
		return conn
	}

	conn = &Conn{
		nc: conn,
		Reader: Reader{
			Reader: conn,
			Cipher: cipher,
		},
		Writer: Writer{
			Writer: conn,
			Cipher: cipher,
		},
	}
	return conn
}

func (c *Conn) Close() error                       { return c.nc.Close() }
func (c *Conn) LocalAddr() net.Addr                { return c.nc.LocalAddr() }
func (c *Conn) RemoteAddr() net.Addr               { return c.nc.RemoteAddr() }
func (c *Conn) SetDeadline(t time.Time) error      { return c.nc.SetDeadline(t) }
func (c *Conn) SetReadDeadline(t time.Time) error  { return c.nc.SetReadDeadline(t) }
func (c *Conn) SetWriteDeadline(t time.Time) error { return c.nc.SetWriteDeadline(t) }

var (
	_ CloseReader = (*Conn)(nil)
	_ CloseWriter = (*Conn)(nil)
	_ net.Conn    = (*Conn)(nil)
)
