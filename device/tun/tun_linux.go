// +build linux

package tun

import (
	"github.com/songgao/water"
)

func NewDevice(n string) (*Device, error) {
	config := water.Config{
		DeviceType: water.TUN,
	}
	config.Name = n
	config.Persist = true

	dev, err := water.New(config)
	if err != nil {
		return nil, err
	}

	return &Device{
		Name:      dev.Name(),
		active:    make(chan struct{}),
		Interface: dev,
	}, nil
}
