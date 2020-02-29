package core

import (
	"encoding/binary"
	"errors"
	"net"
	"strconv"
	"strings"

	"golang.org/x/net/dns/dnsmessage"

	wd "github.com/imgk/WinDivert"
	"github.com/imgk/shadowsocks-windivert/suffixtree"
)

var dnsHandle *wd.Handle
var dnsTable4 = [65536]Netlink{}
var dnsTable6 = [65536]Netlink{}
var matchTree = suffixtree.NewTree(".")

func DivertDNS() {
	const filter string = "outbound and udp and (loopback ? udp.SrcPort = 53 : udp.DstPort = 53)"
	dnsHandle, err := wd.Open(filter, wd.LayerNetwork, wd.PriorityDefault, wd.FlagDefault)
	if err != nil {
		logf("open dns handle error: %v", err)
		return
	}
	if err := dnsHandle.SetParam(wd.QueueLength, wd.QueueLengthMax); err != nil {
		logf("set dns handle parameter queue length error %v", err)
		return
	}
	if err := dnsHandle.SetParam(wd.QueueTime, wd.QueueTimeMax); err != nil {
		logf("set dns handle parameter queue time error %v", err)
		return
	}
	if err := dnsHandle.SetParam(wd.QueueSize, wd.QueueSizeMax); err != nil {
		logf("set dns handle parameter queue size error %v", err)
		return
	}
	defer func() {
		if err := dnsHandle.Shutdown(wd.ShutdownRecv); err != nil {
			logf("shutdown dns handle error: %v", err)
		}

		if err := dnsHandle.Close(); err != nil {
			logf("close dns handle error: %v", err)
		}
	}()

	var a = new(wd.Address)
	var b = make([]byte, 1500)
	var m = new(dnsmessage.Message)
	var l *Netlink

	for {
		n, err := dnsHandle.Recv(b, a)
		if err != nil {
			logf("receive packet from dns handle error: %v", err)
			continue
		}

		if a.Loopback() {
			if a.IPv6() {
				l = &dnsTable6[binary.BigEndian.Uint16(b[42:])]
				copy(b[8:24], l.RemoteAddr[:])
				copy(b[24:40], l.LocalAddr[:])
			} else {
				l = &dnsTable4[binary.BigEndian.Uint16(b[22:])]
				copy(b[12:16], l.RemoteAddr[:])
				copy(b[16:20], l.LocalAddr[:])
			}

			nw := a.Network()
			nw.InterfaceIndex = l.InterfaceIndex
			nw.SubInterfaceIndex = l.SubInterfaceIndex

			a.SetLoopback(false)

			if err := wd.CalcChecksums(b[:n], a.Layer(), a, wd.ChecksumDefault); err != nil {
				logf("calculate checksum error: %v", err)
				continue
			}
		} else {
			if a.IPv6() {
				if err := m.Unpack(b[40+8 : n]); err != nil {
					logf("parse ipv6 dns message error: %v", err)
					continue
				}
			} else {
				if err := m.Unpack(b[20+8 : n]); err != nil {
					logf("parse ipv4 dns message error: %v", err)
					continue
				}
			}

			if len(m.Questions) == 0 {
				logf("length of questions in dns message is 0")
				continue
			}

			name := m.Questions[0].Name.String()
			switch s := matchTree.Load(name); s {
			case "PROXY":
				//logf("PROXY: %v", name)

				if a.IPv6() {
					l = &dnsTable6[binary.BigEndian.Uint16(b[40:])]
					copy(l.LocalAddr[:], b[8:24])
					copy(l.RemoteAddr[:], b[24:40])
					copy(b[8:24], []byte{0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 1})
					copy(b[24:40], []byte{0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 1})
				} else {
					l = &dnsTable4[binary.BigEndian.Uint16(b[20:])]
					copy(l.LocalAddr[:], b[12:16])
					copy(l.RemoteAddr[:], b[16:20])
					copy(b[12:16], []byte{127, 0, 0, 1})
					copy(b[16:20], []byte{127, 0, 0, 1})
				}

				nw := a.Network()
				l.InterfaceIndex = nw.InterfaceIndex
				l.SubInterfaceIndex = nw.SubInterfaceIndex
				nw.InterfaceIndex = 1 // Loopback
				nw.SubInterfaceIndex = 0

				a.SetLoopback(true)

				if err := wd.CalcChecksums(b[:n], a.Layer(), a, wd.ChecksumDefault); err != nil {
					logf("calculate checksum error: %v", err)
					continue
				}
			case "DIRECT":
				//logf("DIRECT: %v", name)
			case "BLOCKED":
				//logf("BLOCKED: %v", name)
				continue
			default:
				//logf("DEFAULT: %v", name)
			}
		}

		if _, err = dnsHandle.Send(b[:n], a); err != nil {
			logf("write back to dns handle error: %v", err)
		}
	}
}

var domainTable = make(map[string][4]byte)
var hostTable = make([]string, 0, 4096)
var errDomainNotFound error = errors.New("domain not found in host table")

func ServeDNS() {
	pc, err := net.ListenPacket("udp", "127.0.0.1:53")
	if err != nil {
		logf("listen udp on 127.0.0.1:53 error: %v", err)
		return
	}
	defer pc.Close()
	logf("serve dns server on %v", pc.LocalAddr())

	var b = make([]byte, 1500)
	var m = new(dnsmessage.Message)

	for {
		n, raddr, err := pc.ReadFrom(b)
		if err != nil {
			logf("receive dns message from %v error: %v", raddr, err)
			continue
		}

		if err := m.Unpack(b[:n]); err != nil {
			logf("parse dns message from %v error: %v", raddr, err)
			continue
		}

		name := m.Questions[0].Name.String()
		switch m.Questions[0].Type {
		case dnsmessage.TypePTR:
			secs := strings.Split(strings.TrimSuffix(name, ".44.in-addr.arpa."), ".")
			i4, err := strconv.Atoi(secs[0])
			if err != nil {
				continue
			}
			i3, err := strconv.Atoi(secs[1])
			if err != nil {
				continue
			}
			i2, err := strconv.Atoi(secs[2])
			if err != nil {
				continue
			}

			i := i4 + i3<<8 + i2<<16
			if i >= len(hostTable) {
				continue
			}
			d := hostTable[i]

			m.Header.RCode = dnsmessage.RCodeSuccess
			m.Answers = append(m.Answers[:0], dnsmessage.Resource{
				Header: dnsmessage.ResourceHeader{
					Name:  m.Questions[0].Name,
					Type:  m.Questions[0].Type,
					Class: m.Questions[0].Class,
					TTL:   5,
				},
				Body: &dnsmessage.PTRResource{PTR: dnsmessage.MustNewName(d)},
			})

			//logf("answer %v result %v to %v", name, d, raddr)
		case dnsmessage.TypeA:
			ip, ok := domainTable[name]
			if !ok {
				l := len(domainTable)
				hostTable = append(hostTable[:l], name)

				ip[0] = 44
				ip[1] = byte(l >> 16)
				binary.BigEndian.PutUint16(ip[2:], uint16(l))

				domainTable[name] = ip
			}

			m.Header.RCode = dnsmessage.RCodeSuccess
			m.Answers = append(m.Answers[:0], dnsmessage.Resource{
				Header: dnsmessage.ResourceHeader{
					Name:  m.Questions[0].Name,
					Type:  m.Questions[0].Type,
					Class: m.Questions[0].Class,
					TTL:   5,
				},
				Body: &dnsmessage.AResource{A: ip},
			})

			//logf("answer %v result %v to %v", name, net.IP(ip[:]), raddr)
		case dnsmessage.TypeAAAA:
			m.Header.RCode = dnsmessage.RCodeRefused
			//logf("answer %v result %v to %v", name, net.IP(ip[:]), raddr)
		default:
			m.Header.RCode = dnsmessage.RCodeRefused
			//logf("answer %v result %v to %v", name, net.IP(ip[:]), raddr)
		}

		m.Header.Response = true
		m.Header.Authoritative = false
		m.Header.Truncated = false
		m.Header.RecursionAvailable = false

		bb, err := m.AppendPack(b[:0])
		if err != nil {
			logf("append pack dns message error: %v", err)
			continue
		}

		if _, err := pc.WriteTo(bb, raddr); err != nil {
			logf("write dns message to %v error: %v", raddr, err)
		}
	}
}
