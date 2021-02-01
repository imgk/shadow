package logger

import (
	"io"
	"log"
)

// Logger is for showing logs of netstack
type Logger interface {
	Error(string, ...interface{})
	Info(string, ...interface{})
	Debug(string, ...interface{})
}

// NewLogger is ...
func NewLogger(w io.Writer) Logger {
	if w == nil {
		return &emptyLogger{}
	}

	logger := &logger{
		err: log.New(w, "Error: ", log.LstdFlags),
		inf: log.New(w, "Infor: ", log.LstdFlags),
		dbg: log.New(w, "Debug: ", log.LstdFlags),
	}
	return logger
}

// logger is for logging
type logger struct {
	err *log.Logger
	inf *log.Logger
	dbg *log.Logger
}

// Error is ...
func (l *logger) Error(s string, v ...interface{}) {
	l.err.Printf(s, v...)
}

// Info is ...
func (l *logger) Info(s string, v ...interface{}) {
	l.inf.Printf(s, v...)
}

// Debug is ...
func (l *logger) Debug(s string, v ...interface{}) {
	l.dbg.Printf(s, v...)
}

// emptyLogger is ...
type emptyLogger struct{}

func (*emptyLogger) Error(s string, v ...interface{}) {}
func (*emptyLogger) Info(s string, v ...interface{})  {}
func (*emptyLogger) Debug(s string, v ...interface{}) {}
