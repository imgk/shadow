// +build pprof

package app

import (
	"log"
	"net/http"
	_ "net/http/pprof"
)

func init() {
	go func() {
		log.Fatal(http.ListenAndServe(":8080", nil))
	}()
}
