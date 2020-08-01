package app

import (
	"context"
	"encoding/json"
	"io"
	"runtime/debug"
	"time"

	"github.com/imgk/shadow/utils"
)

func init() {
	debug.SetGCPercent(10)
	go freeOSMemory(time.NewTicker(time.Minute))
}

func freeOSMemory(ticker *time.Ticker) {
	for range ticker.C {
		debug.FreeOSMemory()
	}
}

type Conf struct {
	Server       []string
	NameServer   string
	FilterString string
	TunName      string
	TunAddr      []string
	IPCIDRRules  struct {
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

func (conf *Conf) Unmarshal(b []byte) error {
	return json.Unmarshal(b, conf)
}

func (conf *Conf) free() {
	conf.AppRules.Proxy = []string{}
	conf.IPCIDRRules.Proxy = []string{}
	conf.DomainRules.Proxy = []string{}
	conf.DomainRules.Direct = []string{}
	conf.DomainRules.Blocked = []string{}
}

type Option struct {
	Conf    *Conf
	Writer  io.Writer
	Ctx     context.Context
	Reload  chan struct{}
	Done    chan struct{}
	Timeout time.Duration
}

func loadDomainRules(matchTree *utils.DomainTree, proxy, direct, blocked []string) {
	matchTree.Lock()
	defer matchTree.Unlock()

	matchTree.UnsafeReset()
	for _, domain := range proxy {
		matchTree.UnsafeStore(domain, "PROXY")
	}
	for _, domain := range direct {
		matchTree.UnsafeStore(domain, "DIRECT")
	}
	for _, domain := range blocked {
		matchTree.UnsafeStore(domain, "BLOCKED")
	}
}
