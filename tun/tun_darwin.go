// +build darwin

package tun

import (
	"github.com/songgao/water"
)

func NewDevice(n string) (*Device, error) {
	config := water.Config{
		DeviceType: water.TUN,
	}

	dev, err := water.New(config)
	if err != nil {
		return nil, err
	}

	return &Device{
		Name: dev.Name(),
		active:    make(chan struct{}),
		Interface: dev,
	}, nil
}
