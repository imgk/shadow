package app

import (
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"os"
	"os/exec"
	"path/filepath"
	"runtime/debug"
	"strings"
	"time"

	"github.com/imgk/shadow/log"
	"github.com/imgk/shadow/utils"
)

var conf Conf

type Conf struct {
	Server       []string
	NameServer   string
	Plugin       string
	PluginOpts   string
	FilterString string
	IPRules      struct {
		Mode   bool
		IPCIDR []string
	}
	AppRules struct {
		Mode     bool
		Programs []string
	}
	DomainRules struct {
		Proxy   []string
		Direct  []string
		Blocked []string
	}
}

func init() {
	debug.SetGCPercent(10)
	go FreeMemory(time.NewTicker(time.Minute))
}

func FreeMemory(ticker *time.Ticker) {
	for range ticker.C {
		debug.FreeOSMemory()
	}
}

func SetConfig(b []byte) error {
	return json.Unmarshal(b, &conf)
}

func GetConfig() ([]byte, error) {
	return json.Marshal(&conf)
}

func LoadDomainRules(matchTree *utils.Tree) {
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

func LoadIPRules(ipfilter *utils.IPFilter) {
	ipfilter.Lock()
	defer ipfilter.Unlock()

	ipfilter.UnsafeReset()
	ipfilter.UnsafeSetMode(conf.IPRules.Mode)

	for _, ip := range conf.IPRules.IPCIDR {
		if err := ipfilter.UnsafeAdd(ip); err != nil {
			log.Logf("add ip rule %v error: %v", ip, err)
		}
	}

	ipfilter.UnsafeSort()
}

func LoadPlugin(name, opts string) (*Plugin, error) {
	log.SetPluginPrefix(name)

	info, err := os.Stat(name)
	if err != nil {
		return nil, err
	}

	if info.IsDir() {
		return nil, errors.New("not a file")
	}

	if !filepath.IsAbs(name) {
		dir, err := os.Getwd()
		if err != nil {
			return nil, err
		}
		name = filepath.Join(dir, name)
	}

	return NewPlugin(name, append([]string{name}, strings.Split(opts, " ")...), log.Writer()), nil
}

type Plugin struct {
	exec.Cmd
	closed chan struct{}
	Pid    int
}

func NewPlugin(name string, args []string, w io.Writer) *Plugin {
	return &Plugin{
		Cmd: exec.Cmd{
			Path:   name,
			Args:   args,
			Stdout: w,
			Stderr: w,
		},
		closed: make(chan struct{}, 1),
	}
}

func (p *Plugin) Start() error {
	if err := p.Cmd.Start(); err != nil {
		return err
	}

	p.Pid = p.Cmd.Process.Pid

	return nil
}

func (p *Plugin) Wait() error {
	if err := p.Cmd.Wait(); err != nil {
		select {
		case <-p.closed:
			return nil
		case <-time.After(time.Second * 5):
			return fmt.Errorf("plugin ends unexpectedly error: %v", err)
		}
	}

	p.closed <- struct{}{}
	return nil
}
