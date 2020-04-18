package windivert

type Layer int

const (
	LayerNetwork        Layer = 0
	LayerNetworkForward Layer = 1
	LayerFlow           Layer = 2
	LayerSocket         Layer = 3
	LayerReflect        Layer = 4
	LayerEthernet       Layer = 5
)

func (l Layer) String() string {
	switch l {
	case LayerNetwork:
		return "WINDIVERT_LAYER_NETWORK"
	case LayerNetworkForward:
		return "WINDIVERT_LAYER_NETWORK_FORWARD"
	case LayerFlow:
		return "WINDIVERT_LAYER_FLOW"
	case LayerSocket:
		return "WINDIVERT_LAYER_SOCKET"
	case LayerReflect:
		return "WINDIVERT_LAYER_REFLECT"
	case LayerEthernet:
		return "WINDIVERT_LAYER_ETHERNET"
	default:
		return ""
	}
}

type Event int

const (
	EventNetworkPacket   Event = 0
	EventFlowEstablished Event = 1
	EventFlowDeleted     Event = 2
	EventSocketBind      Event = 3
	EventSocketConnect   Event = 4
	EventSocketListen    Event = 5
	EventSocketAccept    Event = 6
	EventSocketClose     Event = 7
	EventReflectOpen     Event = 8
	EventReflectClose    Event = 9
	EventEthernetFrame   Event = 10
)

func (e Event) String() string {
	switch e {
	case EventNetworkPacket:
		return "WINDIVERT_EVENT_NETWORK_PACKET"
	case EventFlowEstablished:
		return "WINDIVERT_EVENT_FLOW_ESTABLISHED"
	case EventFlowDeleted:
		return "WINDIVERT_EVENT_FLOW_DELETED"
	case EventSocketBind:
		return "WINDIVERT_EVENT_SOCKET_BIND"
	case EventSocketConnect:
		return "WINDIVERT_EVENT_SOCKET_CONNECT"
	case EventSocketListen:
		return "WINDIVERT_EVENT_SOCKET_LISTEN"
	case EventSocketAccept:
		return "WINDIVERT_EVENT_SOCKET_ACCEPT"
	case EventSocketClose:
		return "WINDIVERT_EVENT_SOCKET_CLOSE"
	case EventReflectOpen:
		return "WINDIVERT_EVENT_REFLECT_OPEN"
	case EventReflectClose:
		return "WINDIVERT_EVENT_REFLECT_CLOSE"
	case EventEthernetFrame:
		return "WINDIVERT_EVENT_ETHERNET_FRAME"
	default:
		return ""
	}
}

type Shutdown int

const (
	ShutdownRecv Shutdown = 0
	ShutdownSend Shutdown = 1
	ShutdownBoth Shutdown = 2
)

func (h Shutdown) String() string {
	switch h {
	case ShutdownRecv:
		return "WINDIVERT_SHUTDOWN_RECV"
	case ShutdownSend:
		return "WINDIVERT_SHUTDOWN_SEND"
	case ShutdownBoth:
		return "WINDIVERT_SHUTDOWN_BOTH"
	default:
		return ""
	}
}

type Param int

const (
	QueueLength  Param = 0
	QueueTime    Param = 1
	QueueSize    Param = 2
	VersionMajor Param = 3
	VersionMinor Param = 4
)

func (p Param) String() string {
	switch p {
	case QueueLength:
		return "WINDIVERT_PARAM_QUEUE_LENGTH"
	case QueueTime:
		return "WINDIVERT_PARAM_QUEUE_TIME"
	case QueueSize:
		return "WINDIVERT_PARAM_QUEUE_SIZE"
	case VersionMajor:
		return "WINDIVERT_PARAM_VERSION_MAJOR"
	case VersionMinor:
		return "WINDIVERT_PARAM_VERSION_MINOR"
	default:
		return ""
	}
}

const (
	FlagDefault   = 0x0000
	FlagSniff     = 0x0001
	FlagDrop      = 0x0002
	FlagRecvOnly  = 0x0004
	FlagSendOnly  = 0x0008
	FlagNoInstall = 0x0010
	FlagFragments = 0x0020
)

const (
	PriorityDefault    = 0
	PriorityHighest    = 3000
	PriorityLowest     = -3000
	QueueLengthDefault = 4096
	QueueLengthMin     = 32
	QueueLengthMax     = 16384
	QueueTimeDefault   = 2000
	QueueTimeMin       = 100
	QueueTimeMax       = 16000
	QueueSizeDefault   = 4194304
	QueueSizeMin       = 65535
	QueueSizeMax       = 33554432
)

const (
	ChecksumDefault  = 0
	NoIPChecksum     = 1
	NoICMPChekcsum   = 2
	NoICMPV6Checksum = 4
	NoTCPChekcsum    = 8
	NoUDPChecksum    = 16
)

const (
	BatchMax = 0xff
	MTUMax   = 40 + 0xffff
)
