package netstack

import (
	"errors"
	"io"

	"github.com/eycorsican/go-tun2socks/core"
)

type Device interface {
	io.Reader
	io.Writer
	io.Closer
}

type Handler interface {
	core.TCPConnHandler
	core.UDPConnHandler
}

type Stack interface {
	io.Reader
	io.Writer
	io.Closer
}

type stack struct {
	stack core.LWIPStack
}

func NewStack(handler Handler, w io.Writer) Stack {
	s := &stack{stack: core.NewLWIPStack()}

	core.RegisterTCPConnHandler(handler)
	core.RegisterUDPConnHandler(handler)
	core.RegisterOutputFn(w.Write)

	return s
}

func (s *stack) Read(b []byte) (int, error) {
	return 0, errors.New("not supported")
}

func (s *stack) WriteTo(w io.Writer) (int64, error) {
	return 0, errors.New("not supported")
}

func (s *stack) Write(b []byte) (int, error) {
	return s.stack.Write(b)
}

func (s *stack) ReadFrom(r io.Reader) (int64, error) {
	b := make([]byte, 1500)
	for {
		n, err := r.Read(b)
		if err != nil {
			return 0, err
		}

		_, err = s.stack.Write(b[:n])
		if err != nil {
			return 0, err
		}
	}
}

func (s *stack) Close() error {
	return s.stack.Close()
}
