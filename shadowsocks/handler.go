package shadowsocks

import (
	"encoding/binary"
	"errors"
	"fmt"
	"io"
	"net"
	"sync"
	"time"

	"github.com/eycorsican/go-tun2socks/core"

	"github.com/imgk/shadowsocks-windivert/dns"
	"github.com/imgk/shadowsocks-windivert/log"
	"github.com/imgk/shadowsocks-windivert/netstack"
	"github.com/imgk/shadowsocks-windivert/utils"
)

type Handler struct {
	sync.Pool
	sync.RWMutex
	Cipher
	raddr   *net.UDPAddr
	addr    string
	timeout time.Duration
	conns   map[core.UDPConn]net.PacketConn
}

func NewHandler(url string, timeout time.Duration) (netstack.Handler, error) {
	addr, cipher, password, err := ParseUrl(url)
	if err != nil {
		return nil, err
	}

	raddr, err := net.ResolveUDPAddr("udp", addr)
	if err != nil {
		return nil, err
	}

	ciph, err := NewCipher(cipher, password)
	if err != nil {
		return nil, err
	}

	return &Handler{
		Pool:    sync.Pool{New: func() interface{} { return make([]byte, 65536) }},
		RWMutex: sync.RWMutex{},
		Cipher:  ciph,
		raddr:   raddr,
		addr:    addr,
		timeout: timeout,
		conns:   make(map[core.UDPConn]net.PacketConn, 16),
	}, nil
}

func (h *Handler) Handle(c net.Conn, target *net.TCPAddr) error {
	errCh := make(chan error, 1)

	go func() {
		defer c.Close()

		addr, err := dns.IPToDomainAddr(target.IP, make([]byte, utils.MaxAddrLen))
		if err != nil {
			errCh <- fmt.Errorf("lookup original address error: %v", err)
			return
		}
		binary.BigEndian.PutUint16(addr[len(addr)-2:], uint16(target.Port))

		rc, err := net.Dial("tcp", h.addr)
		if err != nil {
			errCh <- fmt.Errorf("dial server %v error: %v", h.addr, err)
			return
		}
		rc.(*net.TCPConn).SetKeepAlive(true)
		defer rc.Close()
		rc = NewConn(rc, h.Cipher)

		if _, err := rc.Write(addr); err != nil {
			errCh <- fmt.Errorf("write to server %v error: %v", h.addr, err)
			return
		}

		errCh <- nil

		log.Logf("proxy tcp %v <-> %v <-> %v", c.LocalAddr(), h.addr, addr)

		if err := relay(c.(core.TCPConn), rc.(*Conn)); err != nil {
			if ne, ok := err.(net.Error); ok {
				if ne.Timeout() {
					return
				}
			} else {
				if err == io.EOF {
					return
				}
			}
			log.Logf("relay error: %v", err)
		}
	}()

	return <-errCh
}

func relay(c core.TCPConn, rc *Conn) error {
	errCh := make(chan error, 1)

	go func() {
		_, err := io.Copy(c, rc)
		c.CloseWrite()
		rc.CloseRead()

		errCh <- err
	}()

	_, err := io.Copy(rc, c)
	rc.CloseWrite()
	c.CloseRead()
	if err != nil {
		<-errCh
		return err
	}

	return <-errCh
}

func (h *Handler) Connect(pc core.UDPConn, target *net.UDPAddr) error {
	if target == nil {
		return errors.New("nil target")
	}

	addr, err := dns.IPToDomainAddr(target.IP, make([]byte, utils.MaxAddrLen))
	if err != nil {
		return fmt.Errorf("lookup original address error: %v", err)
	}
	binary.BigEndian.PutUint16(addr[len(addr)-2:], uint16(target.Port))

	rc, err := net.ListenPacket("udp", "")
	if err != nil {
		return err
	}
	rc = NewPacketConn(rc, h.Cipher)

	h.Lock()
	h.conns[pc] = rc
	h.Unlock()

	log.Logf("proxy udp %v <-> %v <-> %v", pc.LocalAddr(), h.addr, addr)

	go func() {
		b := h.Get().([]byte)
		defer h.Put(b)

		for {
			rc.SetDeadline(time.Now().Add(h.timeout))
			n, _, err := rc.ReadFrom(b)
			if err != nil {
				if ne, ok := err.(net.Error); ok {
					if ne.Timeout() {
						break
					}
				}
				log.Logf("read packet error: %v", err)
				break
			}

			raddr, err := utils.ParseAddr(b[:n])
			if err != nil {
				log.Logf("parse addr error: %v", err)
				break
			}

			_, err = pc.WriteFrom(b[len(raddr):n], target)
			if err != nil {
				log.Logf("write packet error: %v", err)
				break
			}
		}

		pc.Close()
		rc.Close()

		h.Lock()
		delete(h.conns, pc)
		h.Unlock()
	}()

	return nil
}

func (h *Handler) ReceiveTo(pc core.UDPConn, data []byte, target *net.UDPAddr) error {
	h.RLock()
	rc, ok := h.conns[pc]
	h.RUnlock()

	if !ok {
		return fmt.Errorf("connection %v->%v does not exist", pc.LocalAddr(), target)
	}

	b := h.Get().([]byte)
	defer h.Put(b)

	addr, err := dns.IPToDomainAddr(target.IP, b)
	if err != nil {
		return fmt.Errorf("lookup original address error: %v", err)
	}
	binary.BigEndian.PutUint16(addr[len(addr)-2:], uint16(target.Port))

	rc.SetDeadline(time.Now().Add(h.timeout))
	_, err = rc.WriteTo(append(addr, data...), h.raddr)
	return err
}
