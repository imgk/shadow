// +build windows

package dns

import (
	"encoding/binary"
	"fmt"
	"net"
	"sync"

	"golang.org/x/net/dns/dnsmessage"
	"golang.org/x/net/ipv4"
	"golang.org/x/net/ipv6"

	"github.com/imgk/shadowsocks-windivert/log"
	"github.com/imgk/shadowsocks-windivert/windivert"
)

var hd *windivert.Handle
var active = make(chan struct{})

func Stop() error {
	select {
	case <-active:
		return nil
	default:
		close(active)
	}
	defer hd.Close()

	if err := hd.Shutdown(windivert.ShutdownBoth); err != nil {
		return fmt.Errorf("shutdown dns handle error: %v", err)
	}

	if err := hd.Close(); err != nil {
		return fmt.Errorf("close dns handle error: %v", err)
	}

	return nil
}

func Serve(server string) error {
	_, server, err := ParseUrl(server)
	if err != nil {
		return err
	}

	r, err := NewResolver(server)
	if server != "" && err != nil {
		return err
	}

	const filter string = "not loopback and outbound and udp and udp.DstPort = 53"
	hd, err = windivert.Open(filter, windivert.LayerNetwork, windivert.PriorityDefault-1, windivert.FlagDefault)
	if err != nil {
		return fmt.Errorf("open dns handle error: %v", err)
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

			select {
			case <-active:
				return nil
			}

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
					if server == "" {
						if _, err := hd.Send(b[:n], a); err != nil {
							select {
							case <-active:
								return
							default:
							}

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
					if server == "" {
						if _, err := hd.Send(b[:n], a); err != nil {
							select {
							case <-active:
								return
							default:
							}

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

			hd.Lock()
			_, err := hd.Send(b[:n], a)
			hd.Unlock()

			if err != nil {
				select {
				case <-active:
					return
				default:
				}

				log.Logf("write back to dns handle error: %v", err)
				return
			}
		}()
	}
}

func SendBack4(b []byte) {
	t := [net.IPv4len]byte{}

	copy(t[:], b[12:12+net.IPv4len])
	copy(b[12:12+net.IPv4len], b[16:16+net.IPv4len])
	copy(b[16:16+net.IPv4len], t[:])
	b[ipv4.HeaderLen+2], b[ipv4.HeaderLen+3] = b[ipv4.HeaderLen+0], b[ipv4.HeaderLen+1]
	b[ipv4.HeaderLen+0], b[ipv4.HeaderLen+1] = 0, 53

	binary.BigEndian.PutUint16(b[2:4], uint16(len(b)))
	binary.BigEndian.PutUint16(b[ipv4.HeaderLen+4:ipv4.HeaderLen+6], uint16(len(b)-ipv4.HeaderLen))
}

func SendBack6(b []byte) {
	t := [net.IPv6len]byte{}

	copy(t[:], b[8:8+net.IPv6len])
	copy(b[8:8+net.IPv6len], b[24:24+net.IPv6len])
	copy(b[24:24+net.IPv6len], t[:])
	b[ipv6.HeaderLen+2], b[ipv6.HeaderLen+3] = b[ipv6.HeaderLen+0], b[ipv6.HeaderLen+1]
	b[ipv6.HeaderLen+0], b[ipv6.HeaderLen+1] = 0, 53

	binary.BigEndian.PutUint16(b[4:6], uint16(len(b)-ipv6.HeaderLen))
	binary.BigEndian.PutUint16(b[ipv6.HeaderLen+4:ipv6.HeaderLen+6], uint16(len(b)-ipv6.HeaderLen))
}
