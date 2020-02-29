package core

import (
	"encoding/json"
	"io/ioutil"
)

func LoadRules(f string) error {
	var rule struct {
		Proxy   []string
		Direct  []string
		Blocked []string
	}

	b, err := ioutil.ReadFile(f)
	if err != nil {
		return err
	}

	err = json.Unmarshal(b, &rule)
	if err != nil {
		return err
	}

	for _, v := range rule.Proxy {
		matchTree.Store(v, "PROXY")
	}

	for _, v := range rule.Direct {
		matchTree.Store(v, "DIRECT")
	}

	for _, v := range rule.Blocked {
		matchTree.Store(v, "BLOCKED")
	}

	matchTree.Store("**.44.in-addr.arpa.", "PROXY")
	return nil
}
