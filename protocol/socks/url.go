package socks

import (
	"errors"
	"net/url"

	"golang.org/x/net/proxy"
)

// ParseURL is ...
func ParseURL(s string) (auth *proxy.Auth, server string, err error) {
	u, er := url.Parse(s)
	if er != nil {
		err = er
		return
	}

	server = u.Host
	if u.User == nil {
		return
	}

	username := u.User.Username()
	password, ok := u.User.Password()
	if !ok {
		err = errors.New("socks url error: no password")
		return
	}
	auth = &proxy.Auth{
		User:     username,
		Password: password,
	}
	return
}
