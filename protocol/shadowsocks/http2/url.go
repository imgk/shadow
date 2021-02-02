package http2

import (
	"errors"
	"net/url"
)

// ParseURL is ...
func ParseURL(s string) (server, method, password string, err error) {
	u, er := url.Parse(s)
	if err != nil {
		err = er
		return
	}

	server = u.Host
	if u.User == nil {
		err = errors.New("no user info")
		return
	}

	method = u.User.Username()

	if s, ok := u.User.Password(); ok {
		password = s
	} else {
		err = errors.New("no password")
	}

	return
}
