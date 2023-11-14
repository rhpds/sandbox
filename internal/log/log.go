package log

import (
	"io"
	"log"
	"log/slog"
	"os"
)

// Err stderr logger
var Err *log.Logger

// Out stdout logger
var Out *log.Logger

// Debug stdout verbose logger
var Debug *log.Logger

// Report stdout logger
var Report *log.Logger

// Structured logger
var Logger *slog.Logger

// InitLoggers sets logger
func InitLoggers(debugFlag bool, attrs []slog.Attr) {
	Err = log.New(os.Stderr, "!!! ", log.LstdFlags)
	Out = log.New(os.Stdout, "    ", log.LstdFlags)

	replaceAttrs := func(groups []string, a slog.Attr) slog.Attr {
		switch a.Key {
		case slog.TimeKey:
			a.Key = "timestamp"
		}
		return a
	}

	opts := slog.HandlerOptions{
		Level:       slog.LevelInfo,
		ReplaceAttr: replaceAttrs,
	}
	if debugFlag {
		Debug = log.New(os.Stdout, "(d) ", log.LstdFlags)
		opts.Level = slog.LevelDebug
	} else {
		Debug = log.New(io.Discard, "(d) ", log.LstdFlags)
	}
	Report = log.New(os.Stdout, "+++ ", log.LstdFlags)

	Logger = slog.New(slog.NewJSONHandler(os.Stdout, &opts).WithAttrs(attrs))
}
