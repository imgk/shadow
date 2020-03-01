package core

import (
	"encoding/binary"
	"errors"
	"fmt"
	"net"
	"strconv"
	"sync"
	"time"

	wd "github.com/imgk/WinDivert"
	"github.com/imgk/shadowsocks-windivert/socks"
)

var udpHandle *wd.Handle
var udpTable4 = [65536]Netlink{}

func DivertUDP() {
	var filter string = fmt.Sprintf("ip and outbound and udp and (loopback ? udp.SrcPort = %v : packet[16] = 44)", strconv.Itoa(int(divertPort)))
	udpHandle, err := wd.Open(filter, wd.LayerNetwork, wd.PriorityDefault, wd.FlagDefault)
	if err != nil {
		logf("open udp handle error: %v", err)
		return
	}
	if err := udpHandle.SetParam(wd.QueueLength, wd.QueueLengthMax); err != nil {
		logf("set udp handle parameter queue length error %v", err)
		return
	}
	if err := udpHandle.SetParam(wd.QueueTime, wd.QueueTimeMax); err != nil {
		logf("set udp handle parameter queue time error %v", err)
		return
	}
	if err := udpHandle.SetParam(wd.QueueSize, wd.QueueSizeMax); err != nil {
		logf("set udp handle parameter queue size error %v", err)
		return
	}
	defer func() {
		if err := udpHandle.Shutdown(wd.ShutdownRecv); err != nil {
			logf("shutdown udp handle error: %v", err)
		}

		if err := udpHandle.Close(); err != nil {
			logf("close udp handle error: %v", err)
		}
	}()

	var a = make([]wd.Address, wd.BatchMax)
	var b = make([]byte, 1500*wd.BatchMax)
	var l *Netlink

	for {
		m, n, err := udpHandle.RecvEx(b, a, nil)
		if err != nil {
			logf("read from udp handle error: %v", err)
			continue
		}

		bb := b[0:]
		for i := range a[:n] {
			aa := &a[i]

			if aa.Loopback() {
				l = &udpTable4[binary.BigEndian.Uint16(bb[22:])]
				copy(bb[12:16], l.RemoteAddr[:])
				copy(bb[16:20], l.LocalAddr[:])
				copy(bb[20:22], l.RemotePort[:])

				nw := aa.Network()
				nw.InterfaceIndex = l.InterfaceIndex
				nw.SubInterfaceIndex = l.SubInterfaceIndex

				aa.SetLoopback(false)
			} else {
				l = &udpTable4[binary.BigEndian.Uint16(bb[20:])]
				copy(l.LocalAddr[:], bb[12:16])
				copy(l.RemoteAddr[:], bb[16:20])
				copy(l.RemotePort[:], bb[22:24])
				copy(bb[12:16], []byte{127, 0, 0, 1})
				copy(bb[16:20], []byte{127, 0, 0, 1})
				binary.BigEndian.PutUint16(bb[22:24], divertPort)

				nw := aa.Network()
				l.InterfaceIndex = nw.InterfaceIndex
				l.SubInterfaceIndex = nw.SubInterfaceIndex
				nw.InterfaceIndex = 1 // Loopback
				nw.SubInterfaceIndex = 0

				aa.SetLoopback(true)
			}

			if err := wd.CalcChecksums(bb[:aa.Length()], aa.Layer(), aa, wd.ChecksumDefault); err != nil {
				logf("calculate checksum error: %v", err)
			}

			bb = bb[aa.Length():]
		}

		_, err = udpHandle.SendEx(b[:m], a[:n], nil)
		if err != nil {
			logf("send packet batch to tcp handle error: %v", err)
		}
	}
}

func ServeUDP(addr string, shadow func(net.PacketConn) net.PacketConn) {
	srvAddr, err := net.ResolveUDPAddr("udp", addr)
	if err != nil {
		logf("resolve udp addr %v, error: %v", addr, err)
		return
	}

	pc, err := net.ListenPacket("udp4", "127.0.0.1:"+strconv.Itoa(int(divertPort)))
	if err != nil {
		logf("listen packet connection error: %v", err)
		return
	}
	defer pc.Close()
	logf("serve udp server on %v", pc.LocalAddr())

	m := nmap{RWMutex: sync.RWMutex{}, table: make(map[string]net.PacketConn), timeout: time.Minute * 5}
	buf := make([]byte, socks.MaxAddrLen+65536)

	for {
		n, raddr, err := pc.ReadFrom(buf[socks.MaxAddrLen:])
		if err != nil {
			logf("read from error: %v", err)
			continue
		}

		target, err := LookupUDPAddr(raddr, make([]byte, socks.MaxAddrLen))
		if err != nil {
			logf("lookup original address error: %v", err)
			continue
		}

		bb := buf[socks.MaxAddrLen-len(target) : socks.MaxAddrLen+n]
		copy(bb, target)

		s := raddr.String()
		if err := m.WriteTo(s, bb, srvAddr); err != nil {
			rc, err := net.ListenPacket("udp", "")
			if err != nil {
				logf("listen packet connection error %v", err)
				continue
			}

			_, err = rc.WriteTo(bb, srvAddr)
			if err != nil {
				logf("write to %v, error: %v", srvAddr, err)
				rc.Close()
				continue
			}

			m.Add(s, rc, pc, raddr)
		}
	}
}

func LookupUDPAddr(raddr net.Addr, b []byte) (socks.Addr, error) {
	var l *Netlink

	if addr, ok := raddr.(*net.UDPAddr); ok {
		l = &udpTable4[addr.Port]
	} else {
		_, port, err := net.SplitHostPort(raddr.String())
		if err != nil {
			return nil, fmt.Errorf("parse host and port error: %v", err)
		}

		p, err := strconv.Atoi(port)
		if err != nil {
			return nil, fmt.Errorf("parse port number error: %v", err)
		}

		l = &udpTable4[p]
	}

	i := int(l.RemoteAddr[1])<<16 + int(binary.BigEndian.Uint16(l.RemoteAddr[2:]))
	if i >= len(hostTable) {
		return nil, errDomainNotFound
	}
	domain := hostTable[i]

	b[0] = socks.AddrTypeDomain
	b[1] = byte(len(domain))
	n := copy(b[2:], domain)
	copy(b[n+2:], l.RemotePort[:])

	return b[:n+4], nil
}

var ErrNotExist = errors.New("not exist error")

type nmap struct {
	sync.RWMutex
	table   map[string]net.PacketConn
	timeout time.Duration
}

func (m *nmap) Add(s string, rc, pc net.PacketConn, raddr net.Addr) {
	m.Lock()
	defer m.Unlock()
	m.table[s] = rc

	go func() {
		if err := timedCopy(rc, pc, raddr, m.timeout); err != nil {
			logf("timed copy to %v", raddr)
		}

		m.Lock()
		defer m.Unlock()
		delete(m.table, s)
		rc.Close()
	}()
}

func (m *nmap) WriteTo(s string, b []byte, addr net.Addr) error {
	m.RLock()
	defer m.RUnlock()

	pc, ok := m.table[s]
	if ok {
		_, err := pc.WriteTo(b, addr)
		return err
	}

	return ErrNotExist
}

func timedCopy(rc net.PacketConn, pc net.PacketConn, raddr net.Addr, timeout time.Duration) error {
	buf := make([]byte, 65536)

	for {
		if err := rc.SetReadDeadline(time.Now().Add(timeout)); err != nil {
			logf("set read deadline error: %v", err)
		}

		n, _, err := rc.ReadFrom(buf)
		if err != nil {
			if ne, ok := err.(net.Error); ok {
				if ne.Timeout() {
					return nil
				}
			}
			return fmt.Errorf("read from error: %v", err)
		}

		srcAddr, err:= socks.ParseAddr(buf[:n])
		if err != nil {
			logf("parse real address error: %v", err)
		}

		// strip original address
		if _, err = pc.WriteTo(buf[len(srcAddr):n], raddr); err != nil {
			return fmt.Errorf("write udp to remote error: %v", err)
		}
	}
}
