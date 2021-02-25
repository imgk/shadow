package trojan

import (
	"crypto/sha256"
	"crypto/tls"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net"
	"os"
	"time"

	"github.com/gorilla/websocket"

	"github.com/imgk/shadow/pkg/gonet"
	"github.com/imgk/shadow/pkg/pool"
	"github.com/imgk/shadow/pkg/socks"
	"github.com/imgk/shadow/proto"
)

func init() {
	fn := func(b json.RawMessage, timeout time.Duration) (gonet.Handler, error) {
		type Proto struct {
			Proto     string `json:"protocol"`
			URL       string `json:"url,omitempty"`
			Server    string `json:"server,omitempty"`
			Password  string `json:"password,omitempty"`
			Path      string `json:"path,omitempty"`
			Transport string `json:"transport,omitempty"`
			Domain    string `json:"domain,omitempty"`
		}
		proto := Proto{}
		if err := json.Unmarshal(b, &proto); err != nil {
			return nil, err
		}

		switch proto.Proto {
		case "trojan", "trojan-go":
			if proto.URL == "" {
				return NewHandler(proto.Server, proto.Path, proto.Password, proto.Transport, proto.Domain, timeout)
			}
			return NewHandlerFromURL(proto.URL, timeout)
		}
		return nil, errors.New("protocol error")
	}

	proto.RegisterNewHandlerFunc("trojan", fn)
	proto.RegisterNewHandlerFunc("trojan-go", fn)
}

// HeaderLen is ...
const HeaderLen = 56

// Handler is ...
type Handler struct {
	// Dialer is ...
	Dialer Dialer
	// Addr is ...
	Addr string

	server  string
	timeout time.Duration
}

// NewHandlerFromURL is ...
func NewHandlerFromURL(s string, timeout time.Duration) (*Handler, error) {
	server, path, password, transport, domain, err := ParseURL(s)
	if err != nil {
		return nil, err
	}
	return NewHandler(server, path, password, transport, domain, timeout)
}

// NewHandler is ...
func NewHandler(server, path, password, transport, domain string, timeout time.Duration) (*Handler, error) {
	proxyAddr, err := net.ResolveUDPAddr("udp", server)
	if err != nil {
		return nil, err
	}

	// generate header
	header := func(password string) [HeaderLen + 2]byte {
		buff := [HeaderLen + 2]byte{}
		hash := sha256.Sum224([]byte(password))
		hex.Encode(buff[:HeaderLen], hash[:])
		buff[HeaderLen], buff[HeaderLen+1] = 0x0d, 0x0a
		return buff
	}(password)

	handler := &Handler{
		Addr:    proxyAddr.String(),
		server:  server,
		timeout: timeout,
	}
	switch transport {
	case "tls":
		handler.Dialer = &TLSDialer{
			Addr: handler.Addr,
			Config: tls.Config{
				ServerName:         domain,
				ClientSessionCache: tls.NewLRUClientSessionCache(32),
			},
			Header: header,
		}
	case "websocket":
		dialer := &WebSocketDialer{
			Addr: fmt.Sprintf("wss://%s%s", domain, path),
			NetDialer: NetDialer{
				Addr: handler.Addr,
			},
			Header: header,
		}
		dialer.Dialer = websocket.Dialer{
			NetDial:        dialer.NetDialer.Dial,
			NetDialContext: dialer.NetDialer.DialContext,
			TLSClientConfig: &tls.Config{
				ServerName:         domain,
				ClientSessionCache: tls.NewLRUClientSessionCache(32),
			},
		}
		handler.Dialer = dialer
	default:
	}

	return handler, nil
}

// Close is ...
func (h *Handler) Close() error {
	if closer, ok := h.Dialer.(io.Closer); ok {
		return closer.Close()
	}
	return nil
}

// Handle is ...
func (h *Handler) Handle(conn gonet.Conn, tgt net.Addr) error {
	defer conn.Close()

	rc, err := h.Dialer.Dial(socks.CmdConnect, tgt)
	if err != nil {
		return err
	}
	defer rc.Close()

	if err := gonet.Relay(conn, rc); err != nil {
		if ne := net.Error(nil); errors.As(err, &ne) {
			if ne.Timeout() {
				return nil
			}
		}
		if errors.Is(err, io.ErrClosedPipe) || errors.Is(err, io.EOF) {
			return nil
		}
		return fmt.Errorf("relay error: %w", err)
	}

	return nil
}

// HandlePacket is ...
func (h *Handler) HandlePacket(conn gonet.PacketConn) error {
	defer conn.Close()

	rc, err := h.Dialer.Dial(socks.CmdAssociate, conn.LocalAddr())
	if err != nil {
		return err
	}
	defer rc.Close()

	const MaxBufferSize = 16 << 10

	// from local to remote
	errCh := make(chan error, 1)
	go func(conn gonet.PacketConn, rc net.Conn, timeout time.Duration, errCh chan error) (err error) {
		sc, b := pool.Pool.Get(MaxBufferSize)
		defer func() {
			pool.Pool.Put(sc)
			if errors.Is(err, io.EOF) || errors.Is(err, os.ErrDeadlineExceeded) {
				err = nil
			}
			errCh <- err
		}()

		b[socks.MaxAddrLen+2], b[socks.MaxAddrLen+3] = 0x0d, 0x0a

		for {
			n, tgt, er := conn.ReadTo(b[socks.MaxAddrLen+4:])
			if er != nil {
				err = er
				break
			}
			b[socks.MaxAddrLen], b[socks.MaxAddrLen+1] = byte(n>>8), byte(n)

			offset, er := func(tgt net.Addr, b []byte) (offset int, err error) {
				if addr, ok := tgt.(*socks.Addr); ok {
					offset = socks.MaxAddrLen - len(addr.Addr)
					copy(b[offset:], addr.Addr)
					return
				}
				if nAddr, ok := tgt.(*net.UDPAddr); ok {
					if ipv4 := nAddr.IP.To4(); ipv4 != nil {
						offset = socks.MaxAddrLen - 1 - net.IPv4len - 2
						b = b[offset:]
						b[0] = socks.AddrTypeIPv4
						copy(b[1:], ipv4)
						b[1+net.IPv4len] = byte(nAddr.Port >> 8)
						b[1+net.IPv4len+1] = byte(nAddr.Port)
					} else {
						ipv6 := nAddr.IP.To16()
						offset = socks.MaxAddrLen - 1 - net.IPv6len - 2
						b = b[offset:]
						b[0] = socks.AddrTypeIPv6
						copy(b[1:], ipv6)
						b[1+net.IPv6len] = byte(nAddr.Port >> 8)
						b[1+net.IPv6len+1] = byte(nAddr.Port)
					}
				} else {
					err = errors.New("Torjan error: addr type error")
				}
				return
			}(tgt, b[:socks.MaxAddrLen])
			if er != nil {
				err = er
				break
			}

			if _, ew := rc.Write(b[offset : socks.MaxAddrLen+4+n]); ew != nil {
				err = ew
				break
			}
		}
		rc.SetReadDeadline(time.Now())
		return
	}(conn, rc, h.timeout, errCh)

	// from remote to local
	sc, b := pool.Pool.Get(MaxBufferSize)
	defer pool.Pool.Put(sc)

	for {
		rc.SetReadDeadline(time.Now().Add(h.timeout))
		raddr, er := socks.ReadAddrBuffer(rc, b)
		if er != nil {
			err = er
			break
		}

		n := len(raddr.Addr)
		if _, er := io.ReadFull(rc, b[n:n+4]); er != nil {
			err = er
			break
		}

		n += (int(b[n])<<8 | int(b[n+1]))
		if _, er := io.ReadFull(rc, b[len(raddr.Addr):n]); er != nil {
			err = er
			break
		}

		if _, ew := conn.WriteFrom(b[len(raddr.Addr):n], raddr); ew != nil {
			err = ew
			break
		}
	}
	conn.SetReadDeadline(time.Now())

	if err == nil || errors.Is(err, io.EOF) || errors.Is(err, os.ErrDeadlineExceeded) {
		err = <-errCh
	} else {
		<-errCh
	}
	return err
}
