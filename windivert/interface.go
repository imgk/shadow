package windivert

import (
	"fmt"
	"net"
	"time"
)

func DialIPv4() {
	conn, err := net.DialTimeout("tcp4", "8.8.8.8:53", time.Second*5)
	if err != nil {
		return
	}

	conn.Close()
}

func DialIPv6() {
	conn, err := net.DialTimeout("tcp6", "[2001:4860:4860::8888]:53", time.Second*5)
	if err != nil {
		return
	}

	conn.Close()
}

func GetInterfaceIndex() (uint32, uint32, error) {
	var filter = "not loopback and outbound and (ip.DstAddr = 8.8.8.8 or ipv6.DstAddr = 2001:4860:4860::8888) and tcp.DstPort = 53"
	hd, err := Open(filter, LayerNetwork, PriorityDefault, FlagSniff)
	if err != nil {
		return 0, 0, fmt.Errorf("open interface handle error: %v", err)
	}
	defer hd.Close()

	go DialIPv4()
	go DialIPv6()

	a := new(Address)
	b := make([]byte, 1500)

	if _, err := hd.Recv(b, a); err != nil {
		return 0, 0, err
	}

	if err := hd.Shutdown(ShutdownBoth); err != nil {
		hd.Close()
		return 0, 0, fmt.Errorf("shutdown interface handle error: %v", err)
	}

	if err := hd.Close(); err != nil {
		return 0, 0, fmt.Errorf("close interface handle error: %v", err)
	}

	nw := a.Network()
	return nw.InterfaceIndex, nw.SubInterfaceIndex, nil
}
