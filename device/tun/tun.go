package tun

import (
	"fmt"
	"net"
)

func Parse4(addr string) ([4]byte, error) {
	if ip := net.ParseIP(addr).To4(); ip != nil {
		return [4]byte{ip[0], ip[1], ip[2], ip[3]}, nil
	}

	return [4]byte{}, fmt.Errorf("parse addr: %v error", addr)
}

func Parse6(addr string) ([16]byte, error) {
	if ip := net.ParseIP(addr).To16(); ip != nil {
		return [16]byte{ip[0], ip[1], ip[2], ip[3], ip[4], ip[5], ip[6], ip[7], ip[8], ip[9], ip[10], ip[11], ip[12], ip[13], ip[14], ip[15]}, nil
	}

	return [16]byte{}, fmt.Errorf("parse addr: %v error", addr)
}

func NewDevice(name string) (*Device, error) {
	return CreateTUN(name, 1500)
}
