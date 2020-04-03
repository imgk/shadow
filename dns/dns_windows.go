// +build windows

package dns

import (
	"encoding/binary"
	"fmt"
	"net/url"
	"strings"
	"sync"

	"golang.org/x/net/dns/dnsmessage"

	"github.com/imgk/shadowsocks-windivert/log"
	"github.com/imgk/shadowsocks-windivert/windivert"
)

var hd *windivert.Handle

func Stop() error {
	if err := hd.Shutdown(windivert.ShutdownBoth); err != nil {
		hd.Close()
		return fmt.Errorf("shutdown dns handle error: %v", err)
	}

	if err := hd.Close(); err != nil {
		return fmt.Errorf("close dns handle error: %v", err)
	}

	return nil
}

func Serve(server string) error {
	r, err := NewResolver(server)
	if server != "" && err != nil {
		return err
	}

	if strings.HasPrefix(server, "https://") || strings.HasPrefix(server, "tls://") {
		u, _ := url.Parse(server)
		server = strings.TrimSuffix(u.Host, ".") + "."
	}

	const filter string = "not loopback and outbound and udp and udp.DstPort = 53"
	hd, err = windivert.Open(filter, windivert.LayerNetwork, windivert.PriorityDefault-1, windivert.FlagDefault)
	if err != nil {
		return fmt.Errorf("open dns handle error: %v", err)
	}
	if err := hd.SetParam(windivert.QueueLength, windivert.QueueLengthMax); err != nil {
		return fmt.Errorf("set dns handle parameter queue length error %v", err)
	}
	if err := hd.SetParam(windivert.QueueTime, windivert.QueueTimeMax); err != nil {
		return fmt.Errorf("set dns handle parameter queue time error %v", err)
	}
	if err := hd.SetParam(windivert.QueueSize, windivert.QueueSizeMax); err != nil {
		return fmt.Errorf("set dns handle parameter queue size error %v", err)
	}
	defer Stop()

	var aPool = sync.Pool{New: func() interface{} { return new(windivert.Address) }}
	var bPool = sync.Pool{New: func() interface{} { return make([]byte, 1024) }}
	var mPool = sync.Pool{New: func() interface{} { return new(dnsmessage.Message) }}

	for {
		a := aPool.Get().(*windivert.Address)
		b := bPool.Get().([]byte)
		m := mPool.Get().(*dnsmessage.Message)

		n, err := hd.Recv(b, a)
		if err != nil {
			aPool.Put(a)
			bPool.Put(b)
			mPool.Put(m)

			if err == windivert.ErrNoData {
				return nil
			}
			return fmt.Errorf("receive dns from handle error: %v", err)
		}

		go func() {
			defer aPool.Put(a)
			defer bPool.Put(b)
			defer mPool.Put(m)

			if a.IPv6() {
				if err := m.Unpack(b[48:n]); err != nil {
					log.Logf("parse ipv6 dns error: %v", err)
					return
				}

				if m, err = ResolveDNS(m); err != nil {
					log.Logf("resolve dns error: %v", err)
					return
				}
				if m.Header.Response {
					bb, err := m.AppendPack(b[:48])
					if err != nil {
						log.Logf("append pack dns message error: %v", err)
						return
					}
					n = uint(len(bb))
				} else {
					if server == "" || server == m.Questions[0].Name.String() {
						if _, err := hd.Send(b[:n], a); err != nil {
							log.Logf("write back to dns handle error: %v", err)
							return
						}
						return
					}

					nr, err := r.Resolve(b[46:], int(n)-48)
					if err != nil {
						log.Logf("resolve dns error: %v", err)
						return
					}
					n = uint(nr) + 48
				}
				SendBack6(b[:n])
			} else {
				if err := m.Unpack(b[28:n]); err != nil {
					log.Logf("parse ipv4 dns error: %v", err)
					return
				}

				if m, err = ResolveDNS(m); err != nil {
					log.Logf("resolve dns error: %v", err)
					return
				}
				if m.Header.Response {
					bb, err := m.AppendPack(b[:28])
					if err != nil {
						log.Logf("append pack dns message error: %v", err)
						return
					}
					n = uint(len(bb))
				} else {
					if server == "" || server == m.Questions[0].Name.String() {
						if _, err := hd.Send(b[:n], a); err != nil {
							log.Logf("write back to dns handle error: %v", err)
							return
						}
						return
					}

					nr, err := r.Resolve(b[26:], int(n)-28)
					if err != nil {
						log.Logf("resolve dns error: %v", err)
						return
					}
					n = uint(nr) + 28
				}
				SendBack4(b[:n])
			}

			a.UnsetOutbound()

			if err := windivert.CalcChecksums(b[:n], windivert.LayerNetwork, nil, windivert.ChecksumDefault); err != nil {
				log.Logf("calculate checksum error: %v", err)
				return
			}

			if _, err := hd.Send(b[:n], a); err != nil {
				log.Logf("write back to dns handle error: %v", err)
				return
			}
		}()
	}
}

func SendBack4(b []byte) {
	t := [4]byte{}

	copy(t[:], b[12:16])
	copy(b[12:16], b[16:20])
	copy(b[16:20], t[:])
	copy(b[22:24], b[20:22])
	copy(b[20:22], []byte{0, 53})

	binary.BigEndian.PutUint16(b[2:4], uint16(len(b)))
	binary.BigEndian.PutUint16(b[24:26], uint16(len(b)-20))
}

func SendBack6(b []byte) {
	t := [16]byte{}

	copy(t[:], b[8:24])
	copy(b[8:24], b[24:40])
	copy(b[24:40], t[:])
	copy(b[42:44], b[40:42])
	copy(b[40:42], []byte{0, 53})

	binary.BigEndian.PutUint16(b[4:6], uint16(len(b)-40))
	binary.BigEndian.PutUint16(b[44:46], uint16(len(b)-40))
}
