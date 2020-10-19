package app

import (
	"encoding/json"
	"errors"
	"io"
	"io/ioutil"
	"net/http"
	"net/http/pprof"
	"os"
	"path/filepath"
	"strings"
	"time"

	"github.com/gorilla/mux"
	"go.uber.org/zap"
	"go.uber.org/zap/zapcore"

	"github.com/imgk/shadow/common"
)

var errNotFile = errors.New("not a file")

type Conf struct {
	Server       string   `json:"server"`
	NameServer   string   `json:"name_server"`
	FilterString string   `json:"windivert_filter_string,omitempty"`
	ProxyServer  string   `json:"proxy_server,omitempty"`
	TunName      string   `json:"tun_name,omitempty"`
	TunAddr      []string `json:"tun_addr,omitempty"`
	IPCIDRRules  struct {
		Proxy []string `json:"proxy"`
	} `json:"ip_cidr_rules"`
	GeoIP struct {
		File   string   `json:"file"`
		Proxy  []string `json:"proxy,omitempty"`
		Bypass []string `json:"bypass,omitempty"`
		Final  string   `json:"final,omitempty"`
	} `json:"geo_ip_rules,omitempty"`
	AppRules struct {
		Proxy []string `json:"proxy"`
	} `json:"app_rules,omitempty"`
	DomainRules struct {
		Proxy   []string `json:"proxy"`
		Direct  []string `json:"direct,omitempty"`
		Blocked []string `json:"blocked,omitempty"`
	} `json:"domain_rules"`
}

type App struct {
	conf   Conf
	router *mux.Router
	server proxyServer

	done    chan struct{}
	config  string
	writer  io.Writer
	logger  *zap.Logger
	timeout time.Duration
	closers []io.Closer
}

func NewApp(file string, timeout time.Duration, w io.Writer) (app *App, err error) {
	if file, err = filepath.Abs(file); err != nil {
		return
	}
	if info, er := os.Stat(file); er == nil {
		if info.IsDir() {
			err = errNotFile
			return
		}
	} else {
		err = er
		return
	}

	app = &App{
		router:  mux.NewRouter(),
		done:    make(chan struct{}),
		config:  file,
		timeout: timeout,
	}
	if env := os.Getenv("PPROF_ENABLED"); env == "1" {
		app.router.HandleFunc("/debug/pprof/cmdline", pprof.Cmdline)
		app.router.HandleFunc("/debug/pprof/profile", pprof.Profile)
		app.router.HandleFunc("/debug/pprof/symbol", pprof.Symbol)
		app.router.HandleFunc("/debug/pprof/trace", pprof.Trace)
		app.router.PathPrefix("/debug/pprof/").Handler(http.HandlerFunc(pprof.Index))
	}
	app.server.router = http.Handler(app)

	if w == nil {
		app.setWriter(emptyWriter{})
	} else {
		app.setWriter(w)
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

func (app *App) setWriter(w io.Writer) {
	app.writer = w
	encoder := zapcore.NewConsoleEncoder(zap.NewDevelopmentEncoderConfig())
	zapcore := zapcore.NewCore(encoder, newWriteSyncer(app.writer), zap.NewAtomicLevelAt(zap.InfoLevel))
	app.logger = zap.New(zapcore, zap.Development())
}

func (app *App) Done() chan struct{} {
	return app.done
}

func (app *App) attachCloser(closer io.Closer) {
	app.closers = append(app.closers, closer)
}

func (app *App) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	if strings.HasPrefix(r.URL.Path, "/debug/pprof/") {
		app.router.ServeHTTP(w, r)
		return
	}
	app.server.ServeHTTP(w, r)
}

func (app *App) Close() {
	select {
	case <-app.done:
		return
	default:
		close(app.done)
	}
	app.server.Close()
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

type emptySyncer struct{ io.Writer }

func (emptySyncer) Sync() error { return nil }

func newWriteSyncer(w io.Writer) zapcore.WriteSyncer {
	if wt, ok := w.(zapcore.WriteSyncer); ok {
		return wt
	}
	return emptySyncer{Writer: w}
}
