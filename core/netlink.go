package core

type Netlink struct {
	InterfaceIndex    uint32
	SubInterfaceIndex uint32
	LocalAddr         [16]byte
	RemoteAddr        [16]byte
	LocalPort         [2]byte
	RemotePort        [2]byte
}
