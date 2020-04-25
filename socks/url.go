package socks

import (
	"errors"
	"net/url"
)

func ParseUrl(s string) (auth *Auth, server string, err error) {
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
		err = errors.New("incomplete socks url")
		return
	}

	auth = &Auth{
		Username: username,
		Password: password,
	}

	return
}
