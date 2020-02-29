package core

import (
	"errors"
	"flag"
	"fmt"
	"net/url"
	"time"

	shadowsocks "github.com/shadowsocks/go-shadowsocks2/core"
)

var verbose bool
var divertPort uint16

func init() {
	divertPort = 8000 + uint16(time.Now().Unix()%1000)
}

func Run() {
	var (
		conf   string
		server string
		udp    bool
	)

	flag.BoolVar(&verbose, "v", false, "enable verbose mode")
	flag.StringVar(&conf, "c", "", "rule config file")
	flag.StringVar(&server, "s", "", "go-shadowsocks2 server url")
	flag.BoolVar(&udp, "u", false, "enable divert udp")
	flag.Parse()

	if err := LoadRules(conf); err != nil {
		panic(fmt.Errorf("load config %v error: %v", conf, err))
	}

	addr, cipher, password, err := ParseUrl(server)
	if err != nil {
		panic(fmt.Errorf("parse shadowsocks url error: %v", err))
	}

	ciph, err := shadowsocks.PickCipher(cipher, make([]byte, 0, 32), password)
	if err != nil {
		panic(fmt.Errorf("generate cipher error: %v", err))
	}

	if udp {
		go ServeUDP(addr, ciph.PacketConn)
		go DivertUDP()
	}

	go ServeTCP(addr, ciph.StreamConn)
	go DivertTCP()

	go ServeDNS()
	go DivertDNS()
}

var errUrl error = errors.New("incomplete shadowsocks url")

func ParseUrl(s string) (addr, cipher, password string, err error) {
	u, er := url.Parse(s)
	if err != nil {
		err = er
		return
	}

	addr = u.Host
	if u.User == nil {
		err = errUrl
		return
	}

	cipher = u.User.Username()

	if s, ok := u.User.Password(); ok {
		password = s
	} else {
		err = errUrl
	}

	return
}
