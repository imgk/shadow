package windivert

import (
	"errors"

	"golang.org/x/net/ipv4"
	"golang.org/x/net/ipv6"
)

func CalcChecksumsEx(buffer []byte, layer Layer, address *Address, flags uint64) (err error) {
	pseudo := [40]byte{}

	switch buffer[0] >> 4 {
	case ipv4.Version:
		buffer[10], buffer[11] = 0, 0
		checksum := combineChecksum(0, calcCheckSum(buffer[:ipv4.HeaderLen]))
		buffer[10], buffer[11] = byte(checksum>>8), byte(checksum)

		copy(pseudo[:8], buffer[12:20])
		pseudo[9], pseudo[10], pseudo[11] = buffer[9], buffer[ipv4.HeaderLen+4], buffer[ipv4.HeaderLen+5]

		switch buffer[9] {
		case TCP:
			buffer[ipv4.HeaderLen+10], buffer[ipv4.HeaderLen+11] = 0, 0
			checksum := combineChecksum(calcCheckSum(pseudo[:12]), calcCheckSum(buffer[ipv4.HeaderLen:]))
			buffer[ipv4.HeaderLen+10], buffer[ipv4.HeaderLen+11] = byte(checksum>>8), byte(checksum)
			return
		case UDP:
			buffer[ipv4.HeaderLen+6], buffer[ipv4.HeaderLen+7] = 0, 0
			checksum := combineChecksum(calcCheckSum(pseudo[:12]), calcCheckSum(buffer[ipv4.HeaderLen:]))
			buffer[ipv4.HeaderLen+6], buffer[ipv4.HeaderLen+7] = byte(checksum>>8), byte(checksum)
		default:
			return
		}
	case ipv6.Version:
		copy(pseudo[:32], buffer[8:40])
		pseudo[39], pseudo[32], pseudo[33] = buffer[5], buffer[ipv6.HeaderLen+4], buffer[ipv6.HeaderLen+5]

		switch buffer[6] {
		case TCP:
			buffer[ipv6.HeaderLen+10], buffer[ipv6.HeaderLen+11] = 0, 0
			checksum := combineChecksum(calcCheckSum(pseudo[:40]), calcCheckSum(buffer[ipv6.HeaderLen:]))
			buffer[ipv6.HeaderLen+10], buffer[ipv6.HeaderLen+11] = byte(checksum>>8), byte(checksum)
			return
		case UDP:
			buffer[ipv6.HeaderLen+6], buffer[ipv6.HeaderLen+7] = 0, 0
			checksum := combineChecksum(calcCheckSum(pseudo[:40]), calcCheckSum(buffer[ipv6.HeaderLen:]))
			buffer[ipv6.HeaderLen+6], buffer[ipv6.HeaderLen+7] = byte(checksum>>8), byte(checksum)
		default:
			return
		}
	default:
		err = errors.New("invalid packet")
	}

	return
}

func combineChecksum(sum, n uint32) uint16 {
	sum += n
	sum = (sum & 0xFFFF) + (sum >> 16)

	return uint16(^(sum + (sum >> 16)))
}

func calcCheckSum(data []byte) (sum uint32) {
	l := len(data)

	if l & 1 != 0 {
		l--
		sum += uint32(data[l]) << 8
	}

	for i := 0; i < l; i += 2 {
		sum += (uint32(data[l]) << 8) | uint32(data[l+1])
	}

	return
}
