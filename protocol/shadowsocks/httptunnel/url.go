package httptunnel

import (
	"fmt"
	"net/url"
)

type UrlError string

func (e UrlError) Error() string {
	return fmt.Sprintf("shadowsocks url error: %v", string(e))
}

func ParseUrl(s string) (server, cipher, password string, err error) {
	u, er := url.Parse(s)
	if err != nil {
		err = er
		return
	}

	server = u.Host
	if u.User == nil {
		err = UrlError("no user info")
		return
	}

	cipher = u.User.Username()

	if s, ok := u.User.Password(); ok {
		password = s
	} else {
		err = UrlError("no password")
	}

	return
}
