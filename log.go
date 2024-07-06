package acme

import (
	"fmt"
	"log"
	stdlog "log"
	"os"
)

type Logger interface {
	Debug(int, string, ...any)
	Info(string, ...any)
	Error(string, ...any)
}

type DefaultLogger struct{}

func NewDefaultLogger() DefaultLogger {
	return DefaultLogger{}
}

func (log DefaultLogger) Debug(level int, format string, args ...any) {
	fmt.Fprintf(os.Stderr, "debug: "+format+"\n", args...)
}

func (log DefaultLogger) Info(format string, args ...any) {
	fmt.Fprintf(os.Stderr, format+"\n", args...)
}

func (log DefaultLogger) Error(format string, args ...any) {
	fmt.Fprintf(os.Stderr, "error: "+format+"\n", args...)
}

type StdErrorLogger struct {
	Log Logger
}

func NewStdErrorLogger(log Logger) *log.Logger {
	return stdlog.New(&StdErrorLogger{Log: log}, "", 0)
}

func (log *StdErrorLogger) Write(data []byte) (int, error) {
	log.Log.Error("%s", string(data))
	return len(data), nil
}
