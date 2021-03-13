package v2ray

import (
	"encoding/json"
	"errors"
	"io"
	"net"
	"os"
	"strconv"
	"time"

	"github.com/v2fly/v2ray-core/v4"

	"github.com/imgk/shadow/pkg/gonet"
	"github.com/imgk/shadow/pkg/pool"
	"github.com/imgk/shadow/proto"
)

func init() {
	fn := func(b json.RawMessage, timeout time.Duration) (gonet.Handler, error) {
		type Proto struct {
			Proto  string          `json:"protocol"`
			URL    string          `json:"url,omitempty"`
			Server string          `json:"server"`
			Config json.RawMessage `json:"v2ray_config"`
		}
		proto := Proto{}
		if err := json.Unmarshal(b, &proto); err != nil {
			return nil, err
		}
		return NewHandler(proto.Config, timeout)
	}

	proto.RegisterNewHandlerFunc("v2ray", fn)
}

// Handler is ...
type Handler struct {
	// Instance is ...
	Instance *core.Instance

	timeout time.Duration
}

// NewHandler is ...
func NewHandler(b json.RawMessage, timeout time.Duration) (*Handler, error) {
	h := &Handler{
		timeout: timeout,
	}
	return h, nil
}

// Close is ...
func (h *Handler) Close() error {
	return h.Instance.Close()
}

// Handle is ...
func (h *Handler) Handle(conn gonet.Conn, tgt net.Addr) error {
	defer conn.Close()

	dest, err := ParseDestination(tgt)
	if err != nil {
		return err
	}
	rc, err := core.Dial(nil, h.Instance, dest)
	if err != nil {
		return err
	}
	defer rc.Close()

	cc := gonet.NewConn(rc)

	errCh := make(chan error, 1)
	go func(conn, cc gonet.Conn, errCh chan error) {
		if _, err := gonet.Copy(conn, cc); err != nil {
			if !errors.Is(err, os.ErrDeadlineExceeded) {
				conn.SetReadDeadline(time.Now())
				conn.CloseWrite()
				errCh <- err
				return
			}
		}
		conn.CloseWrite()
		errCh <- nil
		return
	}(conn, cc, errCh)

	if _, err := gonet.Copy(cc, conn); err != nil {
		if !errors.Is(err, os.ErrDeadlineExceeded) {
			cc.SetReadDeadline(time.Now())
			cc.CloseWrite()
			<-errCh
			return err
		}
	}
	cc.CloseWrite()
	err = <-errCh

	return err
}

// HandlePacket is ...
func (h *Handler) HandlePacket(conn gonet.PacketConn) error {
	defer conn.Close()

	rc, err := core.DialUDP(nil, h.Instance)
	if err != nil {
		return err
	}

	const MaxBufferSize = 16 << 10

	errCh := make(chan error, 1)
	go func(conn gonet.PacketConn, rc net.PacketConn, errCh chan error) (err error) {
		sc, b := pool.Pool.Get(MaxBufferSize)
		defer func() {
			pool.Pool.Put(sc)
			if errors.Is(err, io.EOF) || errors.Is(err, os.ErrDeadlineExceeded) {
				errCh <- nil
				return
			}
			errCh <- err
		}()

		rr := net.Addr(nil)
		tt := &net.UDPAddr{}
		for {
			conn.SetReadDeadline(time.Now().Add(h.timeout))
			n, addr, er := conn.ReadTo(b)
			if er != nil {
				err = er
				break
			}
			if raddr, ok := addr.(*net.UDPAddr); ok {
				if _, ew := rc.WriteTo(b[:n], raddr); ew != nil {
					err = ew
					break
				}
				continue
			}
			if addr == rr {
				if _, ew := rc.WriteTo(b[:n], tt); ew != nil {
					err = ew
					break
				}
				continue
			}
			rr, er = func(addr net.Addr, tt *net.UDPAddr) (net.Addr, error) {
				s := addr.String()
				host, sport, err := net.SplitHostPort(s)
				if err != nil {
					return nil, err
				}
				port, err := strconv.Atoi(sport)
				if err != nil || port < 0 || port > 65535 {
					return nil, errors.New("address port error")
				}
				addrs, err := h.LookupHost(host)
				if err != nil {
					return nil, err
				}
				for _, v := range addrs {
					tt.IP = net.ParseIP(v)
					tt.Port = port
					return addr, nil
				}
				return nil, errors.New("no host error")
			}(addr, tt)
			if er != nil {
				err = er
				break
			}

			if _, ew := rc.WriteTo(b[:n], tt); ew != nil {
				err = ew
				break
			}
		}
		rc.SetReadDeadline(time.Now())
		return
	}(conn, rc, errCh)

	sc, b := pool.Pool.Get(MaxBufferSize)
	defer pool.Pool.Put(sc)

	for {
		n, addr, er := rc.ReadFrom(b)
		if er != nil {
			err = er
			break
		}
		if _, ew := conn.WriteFrom(b[:n], addr); ew != nil {
			err = ew
			break
		}
	}
	conn.SetReadDeadline(time.Now())
	if err == nil || errors.Is(err, io.EOF) || errors.Is(err, os.ErrDeadlineExceeded) {
		err = <-errCh
		return err
	}
	<-errCh

	return err
}

// LookupHost is ...
func (h *Handler) LookupHost(s string) ([]string, error) {
	return []string{}, nil
}
