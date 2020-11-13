package http

import (
	"fmt"
	"net"
	"net/url"
)

type UrlError string

func (e UrlError) Error() string {
	return fmt.Sprintf("http/https url error: %v", string(e))
}

func ParseUrl(s string) (auth, addr, domain, scheme string, err error) {
	u, err := url.Parse(s)
	if err != nil {
		return
	}

	if u.User != nil {
		username := u.User.Username()
		password, ok := u.User.Password()
		if !ok {
			err = UrlError("no password")
			return
		}
		auth = fmt.Sprintf("%v:%v", username, password)
	}

	switch u.Scheme {
	case "http":
		host := u.Hostname()
		port := u.Port()
		if port == "" {
			port = "80"
		}
		addr = net.JoinHostPort(host, port)

		domain = u.Fragment
		if domain == "" {
			domain = host
		}

		scheme = "http"
	case "https":
		host := u.Hostname()
		port := u.Port()
		if port == "" {
			port = "443"
		}
		addr = net.JoinHostPort(host, port)

		domain = u.Fragment
		if domain == "" {
			domain = host
		}

		scheme = "https"
	default:
		err = UrlError("scheme error: " + u.Scheme)
		return
	}

	return
}
