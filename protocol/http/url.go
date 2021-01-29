package http

import (
	"fmt"
	"net"
	"net/url"
)

// URLError is ...
type URLError string

func (e *URLError) Error() string {
	return fmt.Sprintf("http/https url error: %v", string(*e))
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
			e := URLError("no password")
			err = &e
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
	case "https", "http2", "http3":
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

		scheme = u.Scheme
	default:
		e := URLError(fmt.Sprintf("scheme error: %v", u.Scheme))
		err = &e
		return
	}

	return
}
