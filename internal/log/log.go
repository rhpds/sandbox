package log

import (
	"golang.org/x/exp/slog"
	"log"
	"os"
	"io"
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
func InitLoggers(debugFlag bool) {
	Err = log.New(os.Stderr, "!!! ", log.LstdFlags)
	Out = log.New(os.Stdout, "    ", log.LstdFlags)
	opts := slog.HandlerOptions{
		Level: slog.LevelInfo,
	}
	if debugFlag {
		Debug = log.New(os.Stdout, "(d) ", log.LstdFlags)
		opts = slog.HandlerOptions{
			Level: slog.LevelDebug,
		}
	} else {
		Debug = log.New(io.Discard, "(d) ", log.LstdFlags)
	}
	Report = log.New(os.Stdout, "+++ ", log.LstdFlags)

	Logger = slog.New(opts.NewJSONHandler(os.Stdout))
}
