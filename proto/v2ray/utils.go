package v2ray

import (
	"errors"

	"github.com/v2fly/v2ray-core/v4/common/net"

	"github.com/imgk/shadow/pkg/socks"
)

// ParseDestination is ...
func ParseDestination(tgt net.Addr) (net.Destination, error) {
	if saddr, ok := tgt.(*socks.Addr); ok {
		switch saddr.Addr[0] {
		case socks.AddrTypeIPv4, socks.AddrTypeIPv6:
			addr, err := socks.ResolveTCPAddr(saddr)
			if err != nil {
				return net.Destination{}, err
			}
			return net.DestinationFromAddr(addr), nil
		case socks.AddrTypeDomain:
			port := int(saddr.Addr[len(saddr.Addr)-2])<<8 | int(saddr.Addr[len(saddr.Addr)-1])
			dest := net.Destination{
				Address: net.DomainAddress(string(saddr.Addr[2 : 2+saddr.Addr[1]])),
				Port:    net.Port(port),
				Network: net.Network_TCP,
			}
			return dest, nil
		}
		return net.Destination{}, errors.New("socks address type error")
	}
	return net.DestinationFromAddr(tgt), nil
}
