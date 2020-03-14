package windivert

// #cgo CFLAGS: -I${SRCDIR}/Divert/include
// #include "windivert.h"
import "C"

const (
	LayerNetwork        = C.WINDIVERT_LAYER_NETWORK
	LayerNetworkForward = C.WINDIVERT_LAYER_NETWORK_FORWARD
	LayerFlow           = C.WINDIVERT_LAYER_FLOW
	LayerSocket         = C.WINDIVERT_LAYER_SOCKET
	LayerReflect        = C.WINDIVERT_LAYER_REFLECT
	//LayerEthernet       = C.WINDIVERT_LAYER_ETHERNET
)

const (
	EventNetworkPacket   = C.WINDIVERT_EVENT_NETWORK_PACKET
	EventFlowEstablished = C.WINDIVERT_EVENT_FLOW_ESTABLISHED
	EventFlowDeleted     = C.WINDIVERT_EVENT_FLOW_DELETED
	EventSocketBind      = C.WINDIVERT_EVENT_SOCKET_BIND
	EventSocketConnect   = C.WINDIVERT_EVENT_SOCKET_CONNECT
	EventSocketListen    = C.WINDIVERT_EVENT_SOCKET_LISTEN
	EventSocketAccept    = C.WINDIVERT_EVENT_SOCKET_ACCEPT
	EventSocketClose     = C.WINDIVERT_EVENT_SOCKET_CLOSE
	EventReflectOpen     = C.WINDIVERT_EVENT_REFLECT_OPEN
	EventReflectClose    = C.WINDIVERT_EVENT_REFLECT_CLOSE
	//EventEthernetFrame   = C.WINDIVERT_EVENT_ETHERNET_FRAME
)

const (
	ShutdownRecv = C.WINDIVERT_SHUTDOWN_RECV
	ShutDownSend = C.WINDIVERT_SHUTDOWN_SEND
	ShutdownBoth = C.WINDIVERT_SHUTDOWN_BOTH
)

const (
	QueueLength  = C.WINDIVERT_PARAM_QUEUE_LENGTH
	QueueTime    = C.WINDIVERT_PARAM_QUEUE_TIME
	QueueSize    = C.WINDIVERT_PARAM_QUEUE_SIZE
	VersionMajor = C.WINDIVERT_PARAM_VERSION_MAJOR
	VersionMinor = C.WINDIVERT_PARAM_VERSION_MINOR
)

const (
	FlagDefault   = uint64(0)
	FlagSniff     = uint64(C.WINDIVERT_FLAG_SNIFF)
	FlagDrop      = uint64(C.WINDIVERT_FLAG_DROP)
	FlagRecvOnly  = uint64(C.WINDIVERT_FLAG_RECV_ONLY)
	FlagSendOnly  = uint64(C.WINDIVERT_FLAG_SEND_ONLY)
	FlagNoInstall = uint64(C.WINDIVERT_FLAG_NO_INSTALL)
	FlagFragments = uint64(C.WINDIVERT_FLAG_FRAGMENTS)
)

const (
	PriorityDefault    = int16(0)
	PriorityHighest    = int16(C.WINDIVERT_PRIORITY_HIGHEST)
	PriorityLowest     = int16(C.WINDIVERT_PRIORITY_LOWEST)
	QueueLengthDefault = uint64(C.WINDIVERT_PARAM_QUEUE_LENGTH_DEFAULT)
	QueueLengthMin     = uint64(C.WINDIVERT_PARAM_QUEUE_LENGTH_MIN)
	QueueLengthMax     = uint64(C.WINDIVERT_PARAM_QUEUE_LENGTH_MAX)
	QueueTimeDefault   = uint64(C.WINDIVERT_PARAM_QUEUE_TIME_DEFAULT)
	QueueTimeMin       = uint64(C.WINDIVERT_PARAM_QUEUE_TIME_MIN)
	QueueTimeMax       = uint64(C.WINDIVERT_PARAM_QUEUE_TIME_MAX)
	QueueSizeDefault   = uint64(C.WINDIVERT_PARAM_QUEUE_SIZE_DEFAULT)
	QueueSizeMin       = uint64(C.WINDIVERT_PARAM_QUEUE_SIZE_MIN)
	QueueSizeMax       = uint64(C.WINDIVERT_PARAM_QUEUE_SIZE_MAX)
)

const (
	ChecksumDefault  = uint64(0)
	NoIPChecksum     = uint64(C.WINDIVERT_HELPER_NO_IP_CHECKSUM)
	NoICMPChekcsum   = uint64(C.WINDIVERT_HELPER_NO_ICMP_CHECKSUM)
	NoICMPV6Checksum = uint64(C.WINDIVERT_HELPER_NO_ICMPV6_CHECKSUM)
	NoTCPChekcsum    = uint64(C.WINDIVERT_HELPER_NO_TCP_CHECKSUM)
	NoUDPChecksum    = uint64(C.WINDIVERT_HELPER_NO_UDP_CHECKSUM)
)

const (
	BatchMax = int(C.WINDIVERT_BATCH_MAX)
	MTUMax   = int(C.WINDIVERT_MTU_MAX)
)
