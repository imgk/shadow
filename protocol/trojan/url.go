package trojan

import (
	"fmt"
	"net/url"
)

type UrlError string

func (e UrlError) Error() string {
	return fmt.Sprintf("trojan url error: %v", string(e))
}

func ParseUrl(s string) (password, addr, path, transport, muxEnabled, domainName string, err error) {
	u, err := url.Parse(s)
	if err != nil {
		return
	}

	addr = u.Host
	if u.User == nil {
		err = UrlError("no user info")
		return
	}

	if s := u.User.Username(); s != "" {
		password = s
	} else {
		err = UrlError("no password")
		return
	}

	path = u.Path

	transport = u.Query().Get("transport")
	switch transport {
	case "":
		transport = "tls"
	case "tls", "websocket":
	default:
		err = UrlError("wrong transport")
		return
	}

	muxEnabled = u.Query().Get("mux")
	switch muxEnabled {
	case "":
		muxEnabled = "off"
	case "off", "v1", "v2":
	default:
		err = UrlError("wrong mux config")
		return
	}

	domainName = u.Fragment
	if domainName == "" {
		err = UrlError("no domain name")
	}
	return
}
