package log

import (
	"fmt"
	"log"
	"os"
)

var (
	verbose = false
	logger  = log.New(os.Stderr, "", log.Lshortfile|log.LstdFlags)
)

func Verbose() *bool {
	return &verbose
}

func Logf(f string, v ...interface{}) {
	if verbose {
		logger.Output(2, fmt.Sprintf(f, v...))
	}
}
