package app

import (
	"encoding/json"
	"errors"
	"io"
	"io/ioutil"
	"net/http"
	"os"
	"path/filepath"
	"strings"
	"text/template"
	"time"

	"go.uber.org/zap"
	"go.uber.org/zap/zapcore"

	"github.com/imgk/shadow/common"
	"github.com/imgk/shadow/netstack"
)

// shadow application configuration
type Conf struct {
	// Server Config
	Server      string `json:"server"`
	NameServer  string `json:"name_server"`
	ProxyServer string `json:"proxy_server,omitempty"`

	// WinDivert
	FilterString string `json:"windivert_filter_string,omitempty"`
	GeoIP        struct {
		File   string   `json:"file"`
		Proxy  []string `json:"proxy,omitempty"`
		Bypass []string `json:"bypass,omitempty"`
		Final  string   `json:"final"`
	} `json:"geo_ip_rules,omitempty"`
	AppRules struct {
		Proxy []string `json:"proxy"`
	} `json:"app_rules,omitempty"`

	// Tun
	TunName string   `json:"tun_name,omitempty"`
	TunAddr []string `json:"tun_addr,omitempty"`

	// Tun and WinDivert
	IPCIDRRules struct {
		Proxy []string `json:"proxy"`
	} `json:"ip_cidr_rules"`
	DomainRules struct {
		Proxy   []string `json:"proxy"`
		Direct  []string `json:"direct,omitempty"`
		Blocked []string `json:"blocked,omitempty"`
	} `json:"domain_rules"`
}

// read config from file
func (c *Conf) ReadFromFile(file string) error {
	file, err := filepath.Abs(file)
	if err != nil {
		return err
	}

	info, err := os.Stat(file)
	if err != nil {
		return err
	}

	if info.IsDir() {
		return errors.New("not a file")
	}

	b, err := ioutil.ReadFile(file)
	if err != nil {
		return err
	}
	return c.ReadFromByteSlice(b)
}

// load config from byte slice
func (c *Conf) ReadFromByteSlice(b []byte) error {
	if err := json.Unmarshal(b, c); err != nil {
		return err
	}
	for _, v := range c.GeoIP.Proxy {
		c.GeoIP.Proxy = append(c.GeoIP.Proxy, strings.ToUpper(v))
	}
	for _, v := range c.GeoIP.Bypass {
		c.GeoIP.Bypass = append(c.GeoIP.Bypass, strings.ToUpper(v))
	}
	c.GeoIP.Final = strings.ToLower(c.GeoIP.Final)
	return nil
}

// shadow application
type App struct {
	*zap.Logger
	*Conf

	timeout time.Duration

	done    chan struct{}
	closers []io.Closer
}

// new shadow app from config file
func NewApp(file string, timeout time.Duration, w io.Writer) (*App, error) {
	conf := new(Conf)
	if err := conf.ReadFromFile(file); err != nil {
		return nil, err
	}

	return NewAppFromConf(conf, timeout, w), nil
}

// new shadow app from byte slice
func NewAppFromByteSlice(b []byte, timeout time.Duration, w io.Writer) (*App, error) {
	conf := new(Conf)
	if err := conf.ReadFromByteSlice(b); err != nil {
		return nil, err
	}

	return NewAppFromConf(conf, timeout, w), nil
}

// new shadow app from *Conf
func NewAppFromConf(conf *Conf, timeout time.Duration, w io.Writer) *App {
	return &App{
		Logger: zap.New(zapcore.NewCore(
			zapcore.NewConsoleEncoder(zap.NewDevelopmentEncoderConfig()),
			newWriteSyncer(w),
			zap.NewAtomicLevelAt(zap.InfoLevel),
		), zap.Development()),
		Conf:    conf,
		timeout: timeout,
		done:    make(chan struct{}),
		closers: []io.Closer{},
	}
}

func (app *App) attachCloser(closer io.Closer) {
	app.closers = append(app.closers, closer)
}

// done channel
func (app *App) Done() chan struct{} {
	return app.done
}

// shutdown application
func (app *App) Close() error {
	select {
	case <-app.done:
		return nil
	default:
		close(app.done)
	}
	for _, closer := range app.closers {
		closer.Close()
	}
	return nil
}

func (app *App) newDomainTree() (*common.DomainTree, error) {
	tree := common.NewDomainTree(".")
	tree.Lock()
	for _, domain := range app.Conf.DomainRules.Proxy {
		tree.UnsafeStore(domain, &netstack.DomainEntry{Rule: "PROXY"})
	}
	for _, domain := range app.Conf.DomainRules.Direct {
		tree.UnsafeStore(domain, &netstack.DomainEntry{Rule: "DIRECT"})
	}
	for _, domain := range app.Conf.DomainRules.Blocked {
		tree.UnsafeStore(domain, &netstack.DomainEntry{Rule: "BLOCKED"})
	}
	tree.Unlock()
	return tree, nil
}

// empty writer, drop all bytes
type emptyWriter struct{}

func (w emptyWriter) Write(b []byte) (int, error) { return len(b), nil }
func (w emptyWriter) Sync() error                 { return nil }

type emptySyncer struct{ io.Writer }

// empty syncer, always return nil
func (emptySyncer) Sync() error { return nil }

func newWriteSyncer(w io.Writer) zapcore.WriteSyncer {
	if w == nil {
		return emptyWriter{}
	}

	if wt, ok := w.(zapcore.WriteSyncer); ok {
		return wt
	}
	return emptySyncer{Writer: w}
}

func ServePAC(w http.ResponseWriter, r *http.Request) {
	w.Header().Add("Content-Type", "application/x-ns-proxy-autoconfig")
	pacTemplate.Execute(w, r.Host)
}

var pacTemplate = template.Must(template.New("").Parse(`
function FindProxyForURL(url, host) {
    if (isInNet(dnsResolve(host), "198.18.0.0", "255.255.0.0")) {
        return "SOCKS5 {{ . }}; SOCKS {{ . }}; PROXY {{ . }}"
    }
    return "DIRECT"
}
`))
