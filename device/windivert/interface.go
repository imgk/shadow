// +build windows

package windivert

import (
	"fmt"
	"net"
	"sync"
	"time"

	"github.com/imgk/divert-go"
)

// GetInterfaceIndex is ...
func GetInterfaceIndex() (uint32, uint32, error) {
	const filter = "not loopback and outbound and (ip.DstAddr = 8.8.8.8 or ipv6.DstAddr = 2001:4860:4860::8888) and tcp.DstPort = 53"
	hd, err := divert.Open(filter, divert.LayerNetwork, divert.PriorityDefault, divert.FlagSniff)
	if err != nil {
		return 0, 0, fmt.Errorf("open interface handle error: %w", err)
	}
	defer hd.Close()

	wg := &sync.WaitGroup{}

	wg.Add(1)
	go func(wg *sync.WaitGroup) {
		defer wg.Done()

		conn, err := net.DialTimeout("tcp4", "8.8.8.8:53", time.Second)
		if err != nil {
			return
		}

		conn.Close()
	}(wg)

	wg.Add(1)
	go func(wg *sync.WaitGroup) {
		defer wg.Done()

		conn, err := net.DialTimeout("tcp6", "[2001:4860:4860::8888]:53", time.Second)
		if err != nil {
			return
		}

		conn.Close()
	}(wg)

	addr := divert.Address{}
	buff := make([]byte, 1500)

	if _, err := hd.Recv(buff, &addr); err != nil {
		return 0, 0, err
	}

	if err := hd.Shutdown(divert.ShutdownBoth); err != nil {
		return 0, 0, fmt.Errorf("shutdown interface handle error: %w", err)
	}

	if err := hd.Close(); err != nil {
		return 0, 0, fmt.Errorf("close interface handle error: %w", err)
	}

	wg.Wait()

	nw := addr.Network()
	return nw.InterfaceIndex, nw.SubInterfaceIndex, nil
}
