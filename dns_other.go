//+build !windows

package main

import (
	"fmt"
	"net"

	"golang.org/x/net/dns/dnsmessage"
)

func Serve() error {
	pc, err := net.ListenPacket("udp", ":5553")
	defer func() {
		if err := pc.Close(); err != nil {
			panic(fmt.Errorf("close dns server error: %v", err))
		}
	}()

	var b = make([]byte, 1500)
	var m = new(dnsmessage.Message)

	for {
		n, raddr, err := pc.ReadFrom(b[2:])
		if err != nil {
			return fmt.Errorf("receive dns from server error: %v", err)
		}

		if err := m.Unpack(b[2:2+n]); err != nil {
			logf("parse dns error: %v", err)
			continue
		}

		m = ResolveDNS(m)
		if m.Header.Response {
			n, err = SendBack(b[2:], m)
			if err != nil {
				logf("dns send back error: %v", err)
				continue
			}
		} else {
			//TODO
		}

		if _, err := pc.WriteTo(b[:n], raddr); err != nil {
			return fmt.Errorf("write back to dns handle error: %v", err)
		}
	}
}

func SendBack(b []byte, m *dnsmessage.Message) (int, err) {
	bb, err := m.AppendPack(b)
	return len(bb), err
}
