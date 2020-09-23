// +build pprof

package main

import (
	"net/http"
	_ "net/http/pprof"

	"golang.org/x/net/http2"
	"golang.org/x/net/http2/h2c"
)

func init() {
	s := http.Server{
		Addr:    ":8080",
		Handler: h2c.NewHandler(http.DefaultServeMux, &http2.Server{}),
	}
	go s.ListenAndServe()
}
