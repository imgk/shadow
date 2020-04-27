package windivert

type CtlCode uint32

const (
	METHOD_BUFFERED   = 0
	METHOD_IN_DIRECT  = 1
	METHOD_OUT_DIRECT = 2
	METHOD_NEITHER    = 3
)

const (
	FILE_READ_DATA  = 1
	FILE_WRITE_DATA = 2
)

const (
	FILE_DEVICE_NETWORK             = 0x00000012
	FILE_DEVICE_NETWORK_BROWSER     = 0x00000013
	FILE_DEVICE_NETWORK_FILE_SYSTEM = 0x00000014
	FILE_DEVICE_NETWORK_REDIRECTOR  = 0x00000028
)

func CTL_CODE(DeviceType, Function, Method, Access uint32) CtlCode {
	return CtlCode(((DeviceType) << 16) | ((Access) << 14) | ((Function) << 2) | (Method))
}

var (
	IoCtlInitialize = CTL_CODE(FILE_DEVICE_NETWORK, 0x921, METHOD_OUT_DIRECT, FILE_READ_DATA|FILE_WRITE_DATA)
	IoCtlStartup    = CTL_CODE(FILE_DEVICE_NETWORK, 0x922, METHOD_IN_DIRECT, FILE_READ_DATA|FILE_WRITE_DATA)
	IoCtlRecv       = CTL_CODE(FILE_DEVICE_NETWORK, 0x923, METHOD_OUT_DIRECT, FILE_READ_DATA)
	IoCtlSend       = CTL_CODE(FILE_DEVICE_NETWORK, 0x924, METHOD_IN_DIRECT, FILE_READ_DATA|FILE_WRITE_DATA)
	IoCtlSetParam   = CTL_CODE(FILE_DEVICE_NETWORK, 0x925, METHOD_IN_DIRECT, FILE_READ_DATA|FILE_WRITE_DATA)
	IoCtlGetParam   = CTL_CODE(FILE_DEVICE_NETWORK, 0x926, METHOD_OUT_DIRECT, FILE_READ_DATA)
	IoCtlShutdown   = CTL_CODE(FILE_DEVICE_NETWORK, 0x927, METHOD_IN_DIRECT, FILE_READ_DATA|FILE_WRITE_DATA)
)

func (code CtlCode) String() string {
	switch code {
	case IoCtlInitialize:
		return "IOCTL_WINDIVERT_INITIALIZE"
	case IoCtlStartup:
		return "IOCTL_WINDIVERT_STARTUP"
	case IoCtlRecv:
		return "IOCTL_WINDIVERT_RECV"
	case IoCtlSend:
		return "IOCTL_WINDIVERT_SEND"
	case IoCtlSetParam:
		return "IOCTL_WINDIVERT_SET_PARAM"
	case IoCtlGetParam:
		return "IOCTL_WINDIVERT_GET_PARAM"
	case IoCtlShutdown:
		return "IOCTL_WINDIVERT_SHUTDOWN"
	default:
		return ""
	}
}

type IoCtl struct {
	b1, b2, b3, b4 uint32
}

type recv struct {
	Addr       uint64
	AddrLenPtr uint64
}

type send struct {
	Addr    uint64
	AddrLen uint64
}

type initialize struct {
	Layer    uint32
	Priority uint32
	Flags    uint64
}

type startup struct {
	Flags uint64
	_     uint64
}

type shutdown struct {
	How uint32
	_   uint32
	_   uint64
}

type getParam struct {
	Param uint32
	_     uint32
	Value uint64
}

type setParam struct {
	Value uint64
	Param uint32
	_     uint32
}
