package trojan

import (
	"errors"
	"net/url"
)

func ParseUrl(s string) (server, password, mux, path string, err error) {
	u, er := url.Parse(s)
	if er != nil {
		err = er
		return
	}

	server = u.Host
	if u.User == nil {
		err = errors.New("incomplete trojan url")
		return
	}

	if s := u.User.Username(); s != "" {
		password = s
	} else {
		err = errors.New("incomplete trojan url")
		return
	}

	mux, _ = u.User.Password()
	if mux != "" && mux != "mux" {
		err = errors.New("incomplete trojan url")
		return
	}

	path = u.Path
	return
}
