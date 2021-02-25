package trojan

import (
	"errors"
	"net"
	"net/url"
)

// ParseURL is ...
func ParseURL(s string) (server, path, password, transport, domain string, err error) {
	u, err := url.Parse(s)
	if err != nil {
		return
	}

	server = u.Host
	if u.User == nil {
		err = errors.New("no user info")
		return
	}

	if s := u.User.Username(); s != "" {
		password = s
	} else {
		err = errors.New("no password")
		return
	}

	path = u.Path

	transport = u.Query().Get("transport")
	switch transport {
	case "":
		transport = "tls"
	case "tls", "websocket":
	default:
		err = errors.New("wrong transport")
		return
	}

	domain, _, err = net.SplitHostPort(u.Host)
	if err != nil {
		return
	}
	if u.Fragment != "" {
		domain = u.Fragment
	}
	if domain == "" {
		err = errors.New("no domain name")
	}
	return
}
