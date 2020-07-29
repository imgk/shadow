package app

import (
	"encoding/json"
	"net"
	"runtime/debug"
	"time"

	"github.com/imgk/shadow/utils"
)

func init() {
	debug.SetGCPercent(10)
	go FreeMemory(time.NewTicker(time.Minute))
}

func FreeMemory(ticker *time.Ticker) {
	for range ticker.C {
		debug.FreeOSMemory()
	}
}

var conf Conf

type Conf struct {
	Server       []string
	NameServer   string
	FilterString string
	IPRules      struct {
		Proxy []string
	}
	AppRules struct {
		Proxy []string
	}
	DomainRules struct {
		Proxy   []string
		Direct  []string
		Blocked []string
	}
}

func SetConfig(b []byte) error {
	return json.Unmarshal(b, &conf)
}

func GetConfig() ([]byte, error) {
	return json.Marshal(&conf)
}

func LoadDomainRules(matchTree *utils.DomainTree) {
	matchTree.Lock()
	defer matchTree.Unlock()

	matchTree.UnsafeReset()

	for _, v := range conf.DomainRules.Proxy {
		matchTree.UnsafeStore(v, "PROXY")
	}

	for _, v := range conf.DomainRules.Direct {
		matchTree.UnsafeStore(v, "DIRECT")
	}

	for _, v := range conf.DomainRules.Blocked {
		matchTree.UnsafeStore(v, "BLOCKED")
	}
}

func SetDefaultResolver(resolver utils.Resolver) {
	net.DefaultResolver = &net.Resolver{
		PreferGo: true,
		Dial:     resolver.DialContext,
	}
}
