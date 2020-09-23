package trojan

import (
	"fmt"
	"net/url"
)

type UrlError string

func (e UrlError) Error() string {
	return fmt.Sprintf("trojan url error: %v", string(e))
}

func ParseUrl(s string) (opt *Option, err error) {
	opt = &Option{}

	u, err := url.Parse(s)
	if err != nil {
		return
	}

	opt.Server = u.Host
	if u.User == nil {
		err = UrlError("no user info")
		return
	}

	if s := u.User.Username(); s != "" {
		opt.Password = s
	} else {
		err = UrlError("no password")
		return
	}

	opt.Path = u.Path

	query := u.Query()
	if name, ok := query["transport"]; ok {
		opt.Transport = name[0]
		if opt.Transport != "tls" && opt.Path == "" {
			err = UrlError("need path if transport is not tls")
			return
		}
		if opt.Transport != "tls" && opt.Transport != "websocket" {
			err = UrlError("wrong transport")
			return
		}
	} else {
		opt.Transport = "tls"
	}
	if name, ok := query["cipher"]; ok {
		opt.Aead = name[0]
		if opt.Aead != "dummy" && opt.Aead != "chacha20-ietf-poly1305" && opt.Aead != "aes-256-gcm" {
			err = UrlError("wrong aead cipher")
			return
		}
	} else {
		opt.Aead = "dummy"
	}
	if name, ok := query["password"]; ok {
		opt.AeadPassword = name[0]
	} else {
		if opt.Aead != "dummy" {
			err = UrlError("no password for aead")
			return
		}
	}
	if name, ok := query["mux"]; ok {
		opt.Mux = name[0]
		if opt.Mux != "off" && opt.Mux != "v1" && opt.Mux != "v2" {
			err = UrlError("wrong mux config")
			return
		}
	} else {
		opt.Mux = "off"
	}

	opt.DomainName = u.Fragment
	if opt.DomainName == "" {
		err = UrlError("no domain name")
		return
	}
	return
}

type Option struct {
	Password     string
	Server       string
	Path         string
	Transport    string
	Aead         string
	AeadPassword string
	Mux          string
	DomainName   string
}
