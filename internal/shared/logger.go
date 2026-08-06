package shared

import (
	"io"
	"os"
	"time"

	"github.com/rs/zerolog"
)

// NewLogger returns a structured logger. Human-readable console output is used
// when writing to a terminal-attached stderr; JSON otherwise. Logs go to
// stderr only, so stdout stays reserved for report output.
func NewLogger(w io.Writer, verbose bool) zerolog.Logger {
	level := zerolog.WarnLevel
	if verbose {
		level = zerolog.DebugLevel
	}
	if f, ok := w.(*os.File); ok && isCharDevice(f) {
		w = zerolog.ConsoleWriter{Out: f, TimeFormat: time.RFC3339}
	}
	return zerolog.New(w).Level(level).With().Timestamp().Logger()
}

func isCharDevice(f *os.File) bool {
	info, err := f.Stat()
	if err != nil {
		return false
	}
	return info.Mode()&os.ModeCharDevice != 0
}
