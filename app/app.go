package app

import (
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"io/ioutil"
	"net"
	"net/http"
	"net/url"
	"os"
	"path/filepath"
	"strings"
	"time"

	"github.com/imgk/shadow/pkg/logger"
	"github.com/imgk/shadow/pkg/suffixtree"
)

// Conf is shadow application configuration
type Conf struct {
	// Server is ...
	// proxy server
	// ss://chacha20-ietf-poly1305:test1234@1.2.3.4:8388
	Server string `json:"server"`
	// NameServer is ...
	// dns resolver server address
	// tls://1.1.1.1:853
	// https://1.1.1.1:443/dns-query
	NameServer string `json:"name_server"`
	// ProxyServer is ...
	// for incoming socks5/http proxy
	// 127.0.0.1:1080
	ProxyServer string `json:"proxy_server,omitempty"`

	// FilterString is ...
	// WinDivert fitler string
	// generate if not exist
	FilterString string `json:"windivert_filter_string,omitempty"`
	// GeoIP is ...
	// process packets by geo info of target IP
	GeoIP struct {
		// File is ...
		// mmdb file
		File string `json:"file"`
		// Proxy is ...
		Proxy []string `json:"proxy,omitempty"`
		// Bypass is ...
		Bypass []string `json:"bypass,omitempty"`
		// Final is ...
		Final string `json:"final"`
	} `json:"geo_ip_rules,omitempty"`
	// AppRules is ...
	// proxy selected programs
	AppRules struct {
		// Proxy is ...
		Proxy []string `json:"proxy"`
	} `json:"app_rules,omitempty"`

	// TunName is ...
	// for macOS, this should be utun[0-9]
	TunName string `json:"tun_name,omitempty"`
	// TunAddr is ...
	// tun device ip address
	// 192.168.0.11/24
	// fe80:08ef:ae86:68ea::11/64
	TunAddr []string `json:"tun_addr,omitempty"`

	// IPCIDRRules is ...
	// Tun: try to add these cidrs to route table
	// WinDivert: use radix tree to select packets
	IPCIDRRules struct {
		// Proxy is ...
		Proxy []string `json:"proxy"`
	} `json:"ip_cidr_rules"`
	// DomianRules is ...
	// hijack dns queries and process with domain rules
	DomainRules struct {
		// Proxy is ...
		// fake ip with prefix of 198.18 will be assigned
		Proxy []string `json:"proxy"`
		// Direct is ...
		Direct []string `json:"direct,omitempty"`
		// Blocked is ...
		Blocked []string `json:"blocked,omitempty"`
	} `json:"domain_rules"`
}

// prepare is ...
func (c *Conf) prepare() error {
	const Filter44 = "outbound and (ipv6 or (ip and ip.DstAddr != %s and ip.DstAddr != %s))"
	const Filter46 = "outbound and ((ipv6 and ip.DstAddr != %s) or (ip and ip.DstAddr != %s))"
	const Filter66 = "outbound and ((ipv6 and ip.DstAddr != %s and ip.DstAddr != %s) or ip)"

	// ResovleIP is to resovle ip from url
	ResolveIP := func(s string) (net.IP, error) {
		u, err := url.Parse(s)
		if err != nil {
			return nil, err
		}

		addr, err := net.ResolveTCPAddr("tcp", u.Host)
		if err != nil {
			return nil, err
		}

		if ipv4 := addr.IP.To4(); ipv4 != nil {
			return ipv4, nil
		}

		return addr.IP.To16(), nil
	}

	proxyIP, err := ResolveIP(c.Server)
	if err != nil {
		return err
	}

	dnsIP, err := ResolveIP(c.NameServer)
	if err != nil {
		return err
	}

	if len(proxyIP) == net.IPv4len && len(dnsIP) == net.IPv4len {
		c.FilterString = fmt.Sprintf(Filter44, proxyIP, dnsIP)
		return nil
	}
	if len(proxyIP) == net.IPv4len && len(dnsIP) == net.IPv6len {
		c.FilterString = fmt.Sprintf(Filter46, dnsIP, proxyIP)
		return nil
	}
	if len(proxyIP) == net.IPv6len && len(dnsIP) == net.IPv4len {
		c.FilterString = fmt.Sprintf(Filter46, proxyIP, dnsIP)
		return nil
	}
	c.FilterString = fmt.Sprintf(Filter66, proxyIP, dnsIP)
	return nil
}

// ReadFromFile is to read config from file
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

// ReadFromByteSlice is to load config from byte slice
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

// App is shadow application
type App struct {
	// Logger is ....
	Logger logger.Logger
	// Conf is ...
	Conf *Conf

	timeout time.Duration
	closed  chan struct{}
	closers []io.Closer
}

// NewApp is new shadow app from config file
func NewApp(file string, timeout time.Duration, w io.Writer) (*App, error) {
	conf := new(Conf)
	if err := conf.ReadFromFile(file); err != nil {
		return nil, err
	}

	return NewAppFromConf(conf, timeout, w), nil
}

// NewAppFromByteSlice is new shadow app from byte slice
func NewAppFromByteSlice(b []byte, timeout time.Duration, w io.Writer) (*App, error) {
	conf := new(Conf)
	if err := conf.ReadFromByteSlice(b); err != nil {
		return nil, err
	}

	return NewAppFromConf(conf, timeout, w), nil
}

// NewAppFromConf is new shadow app from *Conf
func NewAppFromConf(conf *Conf, timeout time.Duration, w io.Writer) *App {
	app := &App{
		Logger:  logger.NewLogger(w),
		Conf:    conf,
		timeout: timeout,
		closed:  make(chan struct{}),
		closers: []io.Closer{},
	}
	return app
}

// attachCloser is ...
func (app *App) attachCloser(closer io.Closer) {
	app.closers = append(app.closers, closer)
}

// Done is to give done channel
func (app *App) Done() chan struct{} {
	return app.closed
}

// Close is shutdown application
func (app *App) Close() error {
	select {
	case <-app.closed:
		return nil
	default:
	}
	for _, closer := range app.closers {
		closer.Close()
	}
	close(app.closed)
	return nil
}

// NewDomainTree is ...
func NewDomainTree(conf *Conf) (*suffixtree.DomainTree, error) {
	tree := suffixtree.NewDomainTree(".")
	tree.Lock()
	for _, domain := range conf.DomainRules.Proxy {
		tree.UnsafeStore(domain, &suffixtree.DomainEntry{Rule: "PROXY"})
	}
	for _, domain := range conf.DomainRules.Direct {
		tree.UnsafeStore(domain, &suffixtree.DomainEntry{Rule: "DIRECT"})
	}
	for _, domain := range conf.DomainRules.Blocked {
		tree.UnsafeStore(domain, &suffixtree.DomainEntry{Rule: "BLOCKED"})
	}
	tree.Unlock()
	return tree, nil
}

// PAC is ...
type PAC struct {
	// Format is ...
	Format string
}

// NewPACForSocks5 is ...
func NewPACForSocks5() *PAC {
	pac := &PAC{
		Format: `function FindProxyForURL(url, host) {
	if (isInNet(dnsResolve(host), "198.18.0.0", "255.255.0.0")) {
		return "SOCKS5 %s"
	}
	return "DIRECT"
}`,
	}
	return pac
}

// NewPACForHTTP is ...
func NewPACForHTTP() *PAC {
	pac := &PAC{
		Format: `function FindProxyForURL(url, host) {
	if (isInNet(dnsResolve(host), "198.18.0.0", "255.255.0.0")) {
		return "PROXY %s"
	}
	return "DIRECT"
}`,
	}
	return pac
}

// ServeHTTP is to serve proxy pac file
func (p *PAC) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	w.Header().Add("Content-Type", "application/x-ns-proxy-autoconfig")
	fmt.Fprintf(w, p.Format, r.Host)
}
