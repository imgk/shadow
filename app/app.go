package app

import (
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/url"
	"os"
	"path/filepath"
	"strings"
	"time"

	"github.com/imgk/shadow/pkg/geosite"
	"github.com/imgk/shadow/pkg/logger"
	"github.com/imgk/shadow/pkg/suffixtree"
)

// Conf is shadow application configuration
type Conf struct {
	// Server is ...
	// proxy server address
	// {
	//   "protocol": "",
	//   "url": "",
	//   "server": ""
	// }
	// ss://chacha20-ietf-poly1305:test1234@1.2.3.4:8388
	Server json.RawMessage `json:"server"`
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
		// mmdb file path
		File string `json:"file"`
		// Proxy is ...
		// ISO code of countries to be proxied
		Proxy []string `json:"proxy,omitempty"`
		// Bypass is ...
		// ISO code of countries to be bypassed
		Bypass []string `json:"bypass,omitempty"`
		// Final is ...
		// default action when country code does not appears in `Proxy` or `Bypass`
		Final string `json:"final"`
	} `json:"geo_ip_rules,omitempty"`
	// AppRules is ...
	// proxy selected programs
	AppRules struct {
		// Proxy is ...
		Proxy []string `json:"proxy"`
	} `json:"app_rules,omitempty"`

	// Tun is ...
	// config for tun device
	Tun struct {
		// TunName is ...
		// for macOS, this should be utun[0-9]
		TunName string `json:"tun_name,omitempty"`
		// TunAddr is ...
		// tun device ip address
		// 192.168.0.11/24
		// fe80:08ef:ae86:68ea::11/64
		TunAddr []string `json:"tun_addr,omitempty"`
		// NameServer is ...
		NameServer string `json:"name_server,omitempty"`
		// MTU is ...
		// set MTU for tun device
		MTU int `json:"mtu,omitempty"`
		// PreUp is ...
		PreUp string `json:"pre_up,omitempty"`
		// PostUp is ...
		PostUp string `json:"post_up,omitemtpy"`
		// PreDown is ...
		PreDown string `json:"pre_down,omitempty"`
		// PostDown is ...
		PostDown string `json:"post_down,omitempty"`
	} `json:"tun,omitempty"`

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
		// GeoSite is ...
		GeoSite struct {
			// File is ...
			// path to geosite.dat
			File string `json:"file"`
			// Proxy is ...
			Proxy []string `json:"proxy,omitempty"`
			// Bypass is ...
			Bypass []string `json:"bypass,omitempty"`
			// Final is ...
			Final string `json:"final,omitempty"`
		} `json:"geo_site,omitempty"`
		// DisableHijack is ...
		// hijack dns queries
		DisableHijack bool `json:"disable_hijack,omitempty"`
		// Proxy is ...
		// fake ip with prefix of 198.18 will be assigned
		Proxy []string `json:"proxy"`
		// Direct is ...
		// send queries to remote dns server
		Direct []string `json:"direct,omitempty"`
		// Blocked is ...
		// answer 0.0.0.0 or ::0
		Blocked []string `json:"blocked,omitempty"`
	} `json:"domain_rules"`
}

// prepareFilterString is ...
// generate filter string for WinDivert
// ignore packets to dns server and proxy server
func (c *Conf) prepareFilterString() error {
	const Filter44 = "outbound and (ipv6 or (ip and ip.DstAddr != %s and ip.DstAddr != %s))"
	const Filter64 = "outbound and ((ipv6 and ipv6.DstAddr != %s) or (ip and ip.DstAddr != %s))"
	const Filter66 = "outbound and ((ipv6 and ipv6.DstAddr != %s and ipv6.DstAddr != %s) or ip)"

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

	type Proto struct {
		Proto  string `json:"protocol"`
		URL    string `json:"url,omitempty"`
		Server string `json:"server,omitempty"`
	}
	proto := Proto{}
	if err := json.Unmarshal(c.Server, &proto); err != nil {
		return fmt.Errorf("unmarshal server error: %w", err)
	}
	if proto.URL == "" && proto.Server == "" {
		return errors.New("no server address for parsing")
	}
	server := proto.URL
	if server == "" {
		server = fmt.Sprintf("http://%s", proto.Server)
	}

	proxyIP, err := ResolveIP(server)
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
		c.FilterString = fmt.Sprintf(Filter64, dnsIP, proxyIP)
		return nil
	}
	if len(proxyIP) == net.IPv6len && len(dnsIP) == net.IPv4len {
		c.FilterString = fmt.Sprintf(Filter64, proxyIP, dnsIP)
		return nil
	}
	c.FilterString = fmt.Sprintf(Filter66, proxyIP, dnsIP)
	return nil
}

// prepareGeographicalIP is ...
// the country codes should upper letters
func (c *Conf) prepareGeographicalIP() {
	for i, v := range c.GeoIP.Proxy {
		c.GeoIP.Proxy[i] = strings.ToUpper(v)
	}
	for i, v := range c.GeoIP.Bypass {
		c.GeoIP.Bypass[i] = strings.ToUpper(v)
	}
	c.GeoIP.Final = strings.ToLower(c.GeoIP.Final)
}

// prepareGeographicalSite is ...
func (c *Conf) prepareGeographicalSite() {
	for i, v := range c.DomainRules.GeoSite.Proxy {
		c.DomainRules.GeoSite.Proxy[i] = strings.ToLower(v)
	}
	for i, v := range c.DomainRules.GeoSite.Bypass {
		c.DomainRules.GeoSite.Bypass[i] = strings.ToLower(v)
	}
	c.DomainRules.GeoSite.Final = strings.ToLower(c.DomainRules.GeoSite.Final)
}

// ReadFromURL is ...
func (c *Conf) ReadFromURL(s string) error {
	r, err := http.Get(s)
	if err != nil {
		return err
	}
	defer r.Body.Close()
	if r.StatusCode != http.StatusOK {
		return fmt.Errorf("status code error: %v", r.StatusCode)
	}
	b, err := io.ReadAll(r.Body)
	if err != nil {
		return err
	}
	return c.ReadFromByteSlice(b)
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

	b, err := os.ReadFile(file)
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
	if c.FilterString == "" {
		return c.prepareFilterString()
	}
	c.prepareGeographicalIP()
	c.prepareGeographicalSite()
	return nil
}

// App is shadow application
type App struct {
	// Logger is ...
	// to print logs
	Logger logger.Logger
	// Conf is ...
	// shadow configuration
	Conf *Conf
	// Timeout is ...
	// timeout for closing UDP connections
	Timeout time.Duration

	closed  chan struct{}
	closers []io.Closer
}

// NewApp is new shadow app from config file
func NewApp(s string, timeout time.Duration, w io.Writer) (*App, error) {
	conf := &Conf{}
	if strings.HasPrefix(s, "https") || strings.HasPrefix(s, "http") {
		if err := conf.ReadFromURL(s); err != nil {
			return nil, err
		}
	} else {
		if err := conf.ReadFromFile(s); err != nil {
			return nil, err
		}
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
		Timeout: timeout,
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
	// close channel after all io.Closer is closed
	close(app.closed)
	return nil
}

// NewDomainTree is ...
// generate domain tree from configuration
func NewDomainTree(conf *Conf) (*suffixtree.DomainTree, error) {
	tree := suffixtree.NewDomainTree(".")
	tree.Lock()
	for k, v := range map[string][]string{
		"PROXY":   conf.DomainRules.Proxy,
		"DIRECT":  conf.DomainRules.Direct,
		"BLOCKED": conf.DomainRules.Blocked,
	} {
		r := &suffixtree.DomainEntry{Rule: k}
		for _, vv := range v {
			tree.UnsafeStore(vv, r)
		}
	}
	tree.Unlock()
	return tree, nil
}

// NewGeoSiteMatcher is ...
func NewGeoSiteMatcher(conf *Conf) (geosite.Matcher, error) {
	g := &conf.DomainRules.GeoSite
	return geosite.NewMatcher(g.File, g.Proxy, g.Bypass, g.Final)
}

// PAC is ...
// serve proxy pac file
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
