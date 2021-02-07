package http

import (
	"encoding/base64"
	"errors"
	"fmt"
	"net"
	"net/url"
)

// ParseURL
func ParseURL(s string) (auth, addr, domain, scheme string, err error) {
	u, err := url.Parse(s)
	if err != nil {
		return
	}

	if u.User != nil {
		username := u.User.Username()
		password, ok := u.User.Password()
		if !ok {
			err = errors.New("no password")
			return
		}
		auth = fmt.Sprintf("%v:%v", username, password)
		auth = fmt.Sprintf("Basic %v", base64.StdEncoding.EncodeToString([]byte(auth)))
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
		err = fmt.Errorf("scheme error: %v", u.Scheme)
		return
	}

	return
}
