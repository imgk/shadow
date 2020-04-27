package log

import (
	"fmt"
	"io"
	"log"
	"os"
)

type Logger struct {
	*log.Logger
	prefix string
	mode   bool
}

func (l *Logger) Write(b []byte) (int, error) {
	if l.mode {
		l.Logger.Printf("%s: %s", l.prefix, b)
	}

	return len(b), nil
}

func (l *Logger) Writer() io.Writer {
	return io.Writer(l)
}

func (l *Logger) Logf(f string, v ...interface{}) {
	if l.mode {
		l.Logger.Output(2, fmt.Sprintf(f, v...))
	}
}

func (l *Logger) SetPluginPrefix(s string) {
	l.prefix = s
}

func (l *Logger) SetMode(m bool) {
	l.mode = m
}

func (l *Logger) SetOutput(w io.Writer) {
	l.Logger.SetOutput(w)
}

var logger = &Logger{
	Logger: log.New(os.Stderr, "", log.Lshortfile|log.LstdFlags),
	prefix: "",
	mode:   false,
}

func Writer() io.Writer {
	return logger
}

func Logf(f string, v ...interface{}) {
	if logger.mode {
		logger.Logger.Output(2, fmt.Sprintf(f, v...))
	}
}

func SetPluginPrefix(s string) {
	logger.prefix = s
}

func SetMode(m bool) {
	logger.mode = m
}

func SetOutput(w io.Writer) {
	logger.Logger.SetOutput(w)
}
