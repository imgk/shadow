package shadowsocks

import (
	"errors"
	"net/url"
)

func ParseUrl(s string) (server, cipher, password string, err error) {
	u, er := url.Parse(s)
	if err != nil {
		err = er
		return
	}

	server = u.Host
	if u.User == nil {
		err = errors.New("incomplete shadowsocks url: no user info")
		return
	}

	cipher = u.User.Username()

	if s, ok := u.User.Password(); ok {
		password = s
	} else {
		err = errors.New("incomplete shadowsocks url: no password")
	}

	return
}
