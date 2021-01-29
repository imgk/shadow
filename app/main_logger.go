package app

import (
	"io"
	"log"
)

// Logger is for logging
type Logger struct {
	error *log.Logger
	info  *log.Logger
	debug *log.Logger
}

// NewLogger is ...
func NewLogger(w io.Writer) *Logger {
	logger := &Logger{}

	logger.error = log.New(w, "Error: ", log.LstdFlags)
	logger.info = log.New(w, "Infor: ", log.LstdFlags)
	logger.debug = log.New(w, "Debug: ", log.LstdFlags)
	return logger
}

// Error is ...
func (l *Logger) Error(s string, v ...interface{}) {
	l.error.Printf(s, v...)
}

// Info is ...
func (l *Logger) Info(s string, v ...interface{}) {
	l.info.Printf(s, v...)
}

// Debug is ...
func (l *Logger) Debug(s string, v ...interface{}) {
	l.debug.Printf(s, v...)
}

type emptyLogger struct{}

func (*emptyLogger) Error(s string, v ...interface{}) {}
func (*emptyLogger) Info(s string, v ...interface{})  {}
func (*emptyLogger) Debug(s string, v ...interface{}) {}
