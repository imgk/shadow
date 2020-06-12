package trojan

import (
	"errors"
	"net/url"
)

func ParseUrl(s string) (server, cipher, password, mux, path string, err error) {
	u, er := url.Parse(s)
	if er != nil {
		err = er
		return
	}

	server = u.Host
	if u.User == nil {
		err = errors.New("incomplete trojan url: no user info")
		return
	}

	if s := u.User.Username(); s != "" {
		password = s
	} else {
		err = errors.New("incomplete trojan url: no password")
		return
	}

	mux, _ = u.User.Password()
	if mux != "" && mux != "mux" {
		err = errors.New("incomplete trojan url: not mux")
		return
	}

	path = u.Path

	query := u.Query()
	if name, ok := query["shadowsocks"]; ok {
		cipher = name[0]
	} else {
		if path != "" {
			err = errors.New("incomplete trojan url: no aead method")
			return
		}
	}

	return
}
