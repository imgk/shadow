package geosite

import (
	"os"
	"strings"

	"github.com/v2fly/v2ray-core/v4/app/router"
	"google.golang.org/protobuf/proto"
)

// Matcher
type Matcher struct {
	proxy  *router.DomainMatcher
	bypass *router.DomainMatcher
	final  bool
}

// NewMatcher is ...
func NewMatcher(file string, proxy, bypass []string, final string) (Matcher, error) {
	b, err := os.ReadFile(file)
	if err != nil {
		return Matcher{}, err
	}

	list := router.GeoSiteList{}
	if err := proto.Unmarshal(b, &list); err != nil {
		return Matcher{}, err
	}

	d1 := []*router.Domain{}
	d2 := []*router.Domain{}
	for _, geosite := range list.GetEntry() {
		code := geosite.GetCountryCode()
		for _, v := range proxy {
			if strings.EqualFold(v, code) {
				d1 = append(d1, geosite.GetDomain()...)
				break
			}
		}
		for _, v := range bypass {
			if strings.EqualFold(v, code) {
				d2 = append(d2, geosite.GetDomain()...)
				break
			}
		}
	}

	m1 := (*router.DomainMatcher)(nil)
	m2 := (*router.DomainMatcher)(nil)
	if len(d1) > 0 {
		m1, err = router.NewMphMatcherGroup(d1)
		if err != nil {
			return Matcher{}, nil
		}
	}
	if len(d2) > 0 {
		m2, err = router.NewMphMatcherGroup(d2)
		if err != nil {
			return Matcher{}, nil
		}
	}
	return Matcher{proxy: m1, bypass: m2, final: "proxy" == strings.ToLower(final)}, nil
}

// Match is ...
func (m *Matcher) Match(s string) bool {
	if m.proxy != nil {
		if m.proxy.ApplyDomain(s) {
			return true
		}
	}
	if m.bypass != nil {
		if m.bypass.ApplyDomain(s) {
			return false
		}
	}
	return m.final
}
