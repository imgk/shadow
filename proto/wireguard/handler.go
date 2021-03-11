package wireguard

import (
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net"
	"os"
	"strconv"
	"time"

	"golang.zx2c4.com/wireguard/conn"
	"golang.zx2c4.com/wireguard/device"
	"golang.zx2c4.com/wireguard/tun"
	"golang.zx2c4.com/wireguard/tun/netstack"

	"github.com/imgk/shadow/pkg/gonet"
	"github.com/imgk/shadow/pkg/pool"
	"github.com/imgk/shadow/proto"
)

func init() {
	fn := func(b json.RawMessage, timeout time.Duration) (gonet.Handler, error) {
		type Proto struct {
			Proto      string `json:"protocol"`
			URL        string `json:"url,omitempty"`
			Server     string `json:"server"`
			PrivateKey string `json:"private_key"`
			PublicKey  string `json:"public_key"`
			Address    string `json:"address"`
			NameServer string `json:"name_server"`
			AllowedIPs string `json:"allowed_ips"`
			MTU        int    `json:"mtu"`
		}
		proto := Proto{}
		if err := json.Unmarshal(b, &proto); err != nil {
			return nil, err
		}
		if _, err := net.ResolveUDPAddr("udp", proto.Server); err != nil {
			return nil, fmt.Errorf("server address error: %w", err)
		}
		if ip := net.ParseIP(proto.Address); ip == nil {
			return nil, errors.New("address error")
		}
		if ip := net.ParseIP(proto.NameServer); ip == nil {
			return nil, errors.New("name server error")
		}
		setting := fmt.Sprintf(`private_key=%s
public_key=%s
endpoint=%s
allowed_ip=%s`, proto.PrivateKey, proto.PublicKey, proto.Server, proto.AllowedIPs)
		return NewHandler(proto.Address, proto.NameServer, proto.MTU, setting, timeout)
	}

	proto.RegisterNewHandlerFunc("wireguard", fn)
}

// Handler is ...
type Handler struct {
	// Net is ...
	Net *netstack.Net
	// Tun is ...
	Tun tun.Device
	// Device is ...
	Device *device.Device

	// Addr is ...
	Addr string

	setting string
	timeout time.Duration
}

// NewHandler is ...
func NewHandler(addr, dns string, mtu int, setting string, timeout time.Duration) (*Handler, error) {
	tun, tnet, err := netstack.CreateNetTUN([]net.IP{net.ParseIP(addr)}, []net.IP{net.ParseIP(dns)}, mtu)
	if err != nil {
		return nil, err
	}
	dev := device.NewDevice(tun, conn.NewDefaultBind(), device.NewLogger(device.LogLevelSilent, ""))
	dev.IpcSet(setting)
	h := &Handler{
		Net:     tnet,
		Tun:     tun,
		Device:  dev,
		Addr:    addr,
		setting: setting,
		timeout: timeout,
	}
	if err := dev.Up(); err != nil {
		h.Close()
		return nil, err
	}
	return h, nil
}

// Close is ...
func (h *Handler) Close() error {
	h.Device.Close()
	return nil
}

// Handle is ...
func (h *Handler) Handle(conn gonet.Conn, tgt net.Addr) error {
	defer conn.Close()

	rc, err := h.Net.Dial("tcp", tgt.String())
	if err != nil {
		return err
	}
	cc, ok := rc.(gonet.Conn)
	if !ok {
		return errors.New("rc type error")
	}

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

	rc, err := h.Net.DialUDP(nil, nil)
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
				addrs, err := h.Net.LookupHost(host)
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
