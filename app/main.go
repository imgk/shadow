package app

import (
	"encoding/json"
	"io"
	"io/ioutil"
	"time"

	"github.com/imgk/shadow/common"
)

type Conf struct {
	Server       string   `json:"server"`
	NameServer   string   `json:"name_server"`
	FilterString string   `json:"windivert_filter_string"`
	TunName      string   `json:"tun_name"`
	TunAddr      []string `json:"tun_addr"`
	IPCIDRRules  struct {
		Proxy []string `json:"proxy"`
	} `json:"ip_cidr_rules"`
	AppRules struct {
		Proxy []string `json:"proxy"`
	} `json:"app_rules"`
	DomainRules struct {
		Proxy   []string `json:"proxy"`
		Direct  []string `json:"direct"`
		Blocked []string `json:"blocked"`
	} `json:"domain_rules"`
}

type App struct {
	conf    Conf
	done    chan struct{}
	config  string
	writer  io.Writer
	timeout time.Duration
	closers []io.Closer
}

func NewApp(file string, timeout time.Duration) (app *App, err error) {
	app = &App{
		done:    make(chan struct{}),
		config:  file,
		writer:  emptyWriter{},
		timeout: timeout,
	}
	err = app.readConfig()
	return
}

func (app *App) readConfig() error {
	b, err := ioutil.ReadFile(app.config)
	if err != nil {
		return err
	}
	if err := json.Unmarshal(b, &app.conf); err != nil {
		return err
	}
	return nil
}

func (app *App) SetWriter(w io.Writer) {
	app.writer = w
}

func (app *App) Done() chan struct{} {
	return app.done
}

func (app *App) attachCloser(closer io.Closer) {
	app.closers = append(app.closers, closer)
}

func (app *App) Close() {
	select {
	case <-app.done:
		return
	default:
		close(app.done)
	}
	for _, closer := range app.closers {
		closer.Close()
	}
}

func (app *App) loadDomainRules(tree *common.DomainTree) {
	tree.Lock()
	tree.UnsafeReset()
	for _, domain := range app.conf.DomainRules.Proxy {
		tree.UnsafeStore(domain, "PROXY")
	}
	for _, domain := range app.conf.DomainRules.Direct {
		tree.UnsafeStore(domain, "DIRECT")
	}
	for _, domain := range app.conf.DomainRules.Blocked {
		tree.UnsafeStore(domain, "BLOCKED")
	}
	tree.Unlock()
}

type emptyWriter struct{}

func (w emptyWriter) Write(b []byte) (int, error) { return len(b), nil }
func (w emptyWriter) Sync() error                 { return nil }
