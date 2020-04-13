// +build !windows

package dns

import (
	"fmt"
	"net"
	"sync"

	"golang.org/x/net/dns/dnsmessage"

	"github.com/imgk/shadowsocks-windivert/log"
)

var active = make(chan struct{})
var pc net.PacketConn

func Stop() error {
	select {
	case <-active:
		return nil
	default:
		close(active)
	}

	if pc != nil {
		return pc.Close()
	}

	return nil
}

func Serve(server string) error {
	local, remote, err := ParseUrl(server)
	if err != nil {
		return err
	}

	r, err := NewResolver(remote)
	if err != nil {
		return err
	}

	pc, err = net.ListenPacket("udp", local)
	if err != nil {
		return err
	}
	defer Stop()

	var bPool = sync.Pool{New: func() interface{} { return make([]byte, 1024) }}
	var mPool = sync.Pool{New: func() interface{} { return new(dnsmessage.Message) }}

	for {
		b := bPool.Get().([]byte)
		m := mPool.Get().(*dnsmessage.Message)

		n, raddr, err := pc.ReadFrom(b[2:])
		if err != nil {
			bPool.Put(b)
			mPool.Put(m)

			select {
			case <-active:
				return nil
			default:
			}

			return fmt.Errorf("receive dns from packet conn error: %v", err)
		}

		go func() {
			defer bPool.Put(b)
			defer mPool.Put(m)

			if err := m.Unpack(b[2 : 2+n]); err != nil {
				log.Logf("parse dns error: %v", err)
				return
			}

			if m, err = ResolveDNS(m); err != nil {
				log.Logf("resolve dns error: %v", err)
				return
			}

			if m.Header.Response {
				bb, err := m.AppendPack(b[:2])
				if err != nil {
					log.Logf("append pack dns message error: %v", err)
					return
				}
				n = len(bb) - 2
			} else {
				nr, err := r.Resolve(b, n)
				if err != nil {
					log.Logf("resolve dns error: %v", err)
					return
				}
				n = nr
			}

			if _, err := pc.WriteTo(b[2:2+n], raddr); err != nil {
				select {
				case <-active:
					return
				default:
				}

				log.Logf("write back to packet conn error: %v", err)
			}
		}()
	}
}
