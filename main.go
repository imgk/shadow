package main

import (
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"io"
	"io/ioutil"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"time"

	"github.com/imgk/shadowsocks-windivert/log"
	"github.com/imgk/shadowsocks-windivert/utils"
)

var file string

func init() {
	mode := flag.Bool("v", false, "enable verbose mode")
	flag.StringVar(&file, "c", "config.json", "config file")
	flag.Parse()

	log.SetMode(*mode)
}

var conf struct {
	Server       string
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

func loadConfig(f string) error {
	b, err := ioutil.ReadFile(f)
	if err != nil {
		return err
	}

	err = json.Unmarshal(b, &conf)
	if err != nil {
		return err
	}

	return nil
}

func loadDomainRules(matchTree *utils.Tree) {
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

	conf.DomainRules.Proxy = nil
	conf.DomainRules.Direct = nil
	conf.DomainRules.Blocked = nil
}

func loadIPRules(ipfilter *utils.IPFilter) {
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

	conf.IPRules.IPCIDR = nil
}

func loadPlugin(name, opts string) (*Plugin, error) {
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
