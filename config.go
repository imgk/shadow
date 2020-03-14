package main

import (
	"encoding/json"
	"io/ioutil"
)

func loadConfig(f string) (string, error) {
	var cfg struct {
		Server  string
		Proxy   []string
		Direct  []string
		Blocked []string
	}

	b, err := ioutil.ReadFile(f)
	if err != nil {
		return "", err
	}

	err = json.Unmarshal(b, &cfg)
	if err != nil {
		return "", err
	}

	for _, v := range cfg.Proxy {
		matchTree.Store(v, "PROXY")
	}

	for _, v := range cfg.Direct {
		matchTree.Store(v, "DIRECT")
	}

	for _, v := range cfg.Blocked {
		matchTree.Store(v, "BLOCKED")
	}

	return cfg.Server, nil
}
