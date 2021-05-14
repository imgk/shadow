package geosite

import (
	"os"
	"testing"
)

func TestMatch(t *testing.T) {
	if _, err := os.Stat("geosite.dat"); err != nil {
		return
	}

	set := []struct {
		Proxy  []string
		Bypass []string
		Final  string
		Test   map[string]bool
	}{
		{
			Proxy:  []string{},
			Bypass: []string{"CN"},
			Final:  "proxy",
			Test: map[string]bool{
				"google.cn": false,
				"qq.com":    false,
				"baidu.com": false,
				"google.jp": true,
			},
		},
		{
			Proxy:  []string{"CN"},
			Bypass: []string{},
			Final:  "bypass",
			Test: map[string]bool{
				"google.cn": true,
				"baidu.com": true,
				"qq.com":    true,
				"google.jp": false,
			},
		},
	}

	for _, s := range set {
		m, err := NewMatcher("geosite.dat", s.Proxy, s.Bypass, s.Final)
		if err != nil {
			t.Errorf("new matcher error: %v", err)
			break
		}
		for k, v := range s.Test {
			if v != m.Match(k) {
				t.Errorf("match domain: %v", k)
			}
		}
	}
}
