package socks

import (
	"fmt"
	"net/url"
)

type UrlError string

func (e UrlError) Error() string {
	return fmt.Sprintf("socks url error: %v", string(e))
}

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
		err = UrlError("no password")
		return
	}

	auth = &Auth{
		Username: username,
		Password: password,
	}

	return
}
