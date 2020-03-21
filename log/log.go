package log

import (
	"fmt"
	"io"
	"log"
	"os"
)

type Logger struct {
	*log.Logger
	format string
	mode   bool
}

func (l *Logger) Write(b []byte) (int, error) {
	if l.mode {
		l.Logger.Printf(l.format, b)
	}

	return len(b), nil
}

var logger = &Logger{
	Logger: log.New(os.Stderr, "", log.Lshortfile|log.LstdFlags),
	format: "",
	mode:   false,
}

func Verbose() *bool {
	return &logger.mode
}

func Writer(prefix string) io.Writer {
	logger.format = prefix + " %s\n"
	return logger
}

func Logf(f string, v ...interface{}) {
	if logger.mode {
		logger.Logger.Output(2, fmt.Sprintf(f, v...))
	}
}
