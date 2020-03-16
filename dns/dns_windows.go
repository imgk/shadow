// +build windows

package dns

import (
	"encoding/binary"
	"fmt"

	"golang.org/x/net/dns/dnsmessage"

	"github.com/imgk/shadowsocks-windivert/log"
	"github.com/imgk/shadowsocks-windivert/windivert"
)

func Serve() error {
	const filter string = "not loopback and outbound and udp and udp.DstPort = 53"
	hd, err := windivert.Open(filter, windivert.LayerNetwork, windivert.PriorityDefault, windivert.FlagDefault)
	if err != nil {
		panic(fmt.Errorf("open dns handle error: %v", err))
	}
	if err := hd.SetParam(windivert.QueueLength, windivert.QueueLengthMax); err != nil {
		panic(fmt.Errorf("set dns handle parameter queue length error %v", err))
	}
	if err := hd.SetParam(windivert.QueueTime, windivert.QueueTimeMax); err != nil {
		panic(fmt.Errorf("set dns handle parameter queue time error %v", err))
	}
	if err := hd.SetParam(windivert.QueueSize, windivert.QueueSizeMax); err != nil {
		panic(fmt.Errorf("set dns handle parameter queue size error %v", err))
	}
	defer func() {
		if err := hd.Shutdown(windivert.ShutdownBoth); err != nil {
			panic(fmt.Errorf("shutdown dns handle error: %v", err))
		}

		if err := hd.Close(); err != nil {
			panic(fmt.Errorf("close dns handle error: %v", err))
		}
	}()

	var a = new(windivert.Address)
	var b = make([]byte, 2048)
	var m = new(dnsmessage.Message)

	for {
		n, err := hd.Recv(b, a)
		if err != nil {
			return fmt.Errorf("receive dns from handle error: %v", err)
		}

		if a.IPv6() {
			if err := m.Unpack(b[48:n]); err != nil {
				log.Logf("parse ipv6 dns error: %v", err)
				continue
			}
		} else {
			if err := m.Unpack(b[28:n]); err != nil {
				log.Logf("parse ipv4 dns error: %v", err)
				continue
			}
		}

		m = ResolveDNS(m)
		if m.Header.Response {
			n, err = SendBack(b, m, a)
			if err != nil {
				log.Logf("dns send back error: %v", err)
				continue
			}
		}

		if _, err := hd.Send(b[:n], a); err != nil {
			return fmt.Errorf("write back to dns handle error: %v", err)
		}
	}
}

func SendBack(b []byte, m *dnsmessage.Message, a *windivert.Address) (uint, error) {
	t := make([]byte, 16)
	n := uint(0)

	if a.IPv6() {
		bb, err := m.AppendPack(b[:48])
		if err != nil {
			return 0, fmt.Errorf("append pack dns message error: %v", err)
		}
		n = uint(len(bb))

		copy(t, b[8:24])
		copy(b[8:24], b[24:40])
		copy(b[24:40], t)
		copy(b[42:44], b[40:42])
		copy(b[40:42], []byte{0, 53})

		binary.BigEndian.PutUint16(b[44:46], uint16(n)-40)
	} else {
		bb, err := m.AppendPack(b[:28])
		if err != nil {
			return 0, fmt.Errorf("append pack dns message error: %v", err)
		}
		n = uint(len(bb))

		copy(t, b[12:16])
		copy(b[12:16], b[16:20])
		copy(b[16:20], t)
		copy(b[22:24], b[20:22])
		copy(b[20:22], []byte{0, 53})

		binary.BigEndian.PutUint16(b[2:4], uint16(n))
		binary.BigEndian.PutUint16(b[24:26], uint16(n)-20)
	}

	a.UnsetOutbound()

	if err := windivert.CalcChecksums(b[:n], windivert.LayerNetwork, nil, windivert.ChecksumDefault); err != nil {
		return 0, fmt.Errorf("calculate checksum error: %v", err)
	}

	return n, nil
}
