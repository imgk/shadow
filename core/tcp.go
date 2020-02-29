package core

import (
	"encoding/binary"
	"fmt"
	"io"
	"net"
	"strconv"
	"time"

	wd "github.com/imgk/WinDivert"
	"github.com/imgk/shadowsocks-windivert/socks"
)

var tcpHandle *wd.Handle
var tcpTable4 = [65536]Netlink{}

func DivertTCP() {
	var filter string = fmt.Sprintf("ip and outbound and tcp and (loopback ? tcp.SrcPort = %v : packet[16] = 44)", int(divertPort))
	tcpHandle, err := wd.Open(filter, wd.LayerNetwork, wd.PriorityDefault, wd.FlagDefault)
	if err != nil {
		logf("open tcp handle error: %v", err)
		return
	}
	if err := tcpHandle.SetParam(wd.QueueLength, wd.QueueLengthMax); err != nil {
		logf("set tcp handle parameter queue length error %v", err)
		return
	}
	if err := tcpHandle.SetParam(wd.QueueTime, wd.QueueTimeMax); err != nil {
		logf("set tcp handle parameter queue time error %v", err)
		return
	}
	if err := tcpHandle.SetParam(wd.QueueSize, wd.QueueSizeMax); err != nil {
		logf("set tcp handle parameter queue size error %v", err)
		return
	}
	defer func() {
		if err := tcpHandle.Shutdown(wd.ShutdownRecv); err != nil {
			logf("shutdown tcp handle error: %v", err)
		}

		if err := tcpHandle.Close(); err != nil {
			logf("close tcp handle error: %v", err)
		}
	}()

	var a = make([]wd.Address, wd.BatchMax)
	var b = make([]byte, 1500*wd.BatchMax)
	var l *Netlink

	for {
		m, n, err := tcpHandle.RecvEx(b, a, nil)
		if err != nil {
			logf("read from tcp handle error: %v", err)
			continue
		}

		bb := b[0:]
		for i := range a[:n] {
			aa := &a[i]

			if aa.Loopback() {
				l = &tcpTable4[binary.BigEndian.Uint16(bb[22:])]
				copy(bb[12:16], l.RemoteAddr[:])
				copy(bb[16:20], l.LocalAddr[:])
				copy(bb[20:22], l.RemotePort[:])

				nw := aa.Network()
				nw.InterfaceIndex = l.InterfaceIndex
				nw.SubInterfaceIndex = l.SubInterfaceIndex

				aa.SetLoopback(false)
			} else {
				l = &tcpTable4[binary.BigEndian.Uint16(bb[20:])]
				if bb[33] == byte(1)<<1 { // SYN
					copy(l.LocalAddr[:], bb[12:16])
					copy(l.RemoteAddr[:], bb[16:20])
					copy(l.RemotePort[:], bb[22:24])
				}

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

		_, err = tcpHandle.SendEx(b[:m], a[:n], nil)
		if err != nil {
			logf("send packet batch to tcp handle error: %v", err)
		}
	}
}

func ServeTCP(addr string, shadow func(net.Conn) net.Conn) {
	l, err := net.Listen("tcp4", "127.0.0.1:"+strconv.Itoa(int(divertPort)))
	if err != nil {
		logf("listen on 127.0.0.1:%v, error: %v", divertPort, err)
		return
	}
	logf("serve tcp server on %v", l.Addr())

	for {
		c, err := l.Accept()
		if err != nil {
			logf("accept new connections from 127.0.0.1:%v, error: %v", divertPort, err)
			continue
		}

		go func() {
			defer c.Close()
			c.(*net.TCPConn).SetKeepAlive(true)

			target, err := LookupTCPAddr(c.RemoteAddr(), make([]byte, socks.MaxAddrLen))
			if err != nil {
				logf("lookup original address error: %v", err)
				return
			}

			rc, err := net.Dial("tcp", addr)
			if err != nil {
				logf("dial server %v error: %v", addr, err)
				return
			}
			rc.(*net.TCPConn).SetKeepAlive(true)
			defer rc.Close()
			rc = shadow(rc)

			logf("proxy %v <-> %v <-> %v", c.RemoteAddr(), addr, target)

			if _, err := rc.Write(target); err != nil {
				logf("write to server %v error: %v", addr, err)
				return
			}

			if err := relay(c, rc); err != nil {
				if ne, ok := err.(net.Error); ok {
					if ne.Timeout() {
						return
					}
				}
				logf("relay error: %v", err)
			}
		}()
	}
}

func LookupTCPAddr(raddr net.Addr, b []byte) (socks.Addr, error) {
	var l *Netlink

	if addr, ok := raddr.(*net.TCPAddr); ok {
		l = &tcpTable4[addr.Port]
	} else {
		_, port, err := net.SplitHostPort(raddr.String())
		if err != nil {
			return nil, fmt.Errorf("parse host and port error: %v", err)
		}

		p, err := strconv.Atoi(port)
		if err != nil {
			return nil, fmt.Errorf("parse port number error: %v", p)
		}

		l = &tcpTable4[p]
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

func relay(l, r net.Conn) error {
	errCh := make(chan error, 1)

	go func() {
		_, err := io.Copy(l, r)
		r.SetDeadline(time.Now())
		l.SetDeadline(time.Now())

		errCh <- err
	}()

	_, err := io.Copy(r, l)
	r.SetDeadline(time.Now())
	l.SetDeadline(time.Now())
	if err != nil {
		<-errCh
		return err
	}

	return <-errCh
}
