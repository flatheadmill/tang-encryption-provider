package logger

import (
	"github.com/rs/zerolog"
	"io"
	"os"
	"time"
)

type Logger struct {
	zl zerolog.Logger
}

func New(w io.Writer) Logger {
	zerolog.TimeFieldFormat = time.RFC3339Nano
	zerolog.TimestampFunc = func() time.Time {
		return time.Now().UTC()
	}

	return Logger{zl: zerolog.New(w).Level(zerolog.InfoLevel).With().Timestamp().Logger()}
}

func (l *Logger) Console() {
	l.zl = l.zl.Output(zerolog.ConsoleWriter{Out: os.Stderr})
}

func (l Logger) Msgf(format string, a ...any) {
	l.logEvent().Msgf(format, a...)
}

func (l Logger) Msg(msg string) {
	l.logEvent().Msg(msg)
}

func (l Logger) Err(err error) bool {
	if err == nil {
		return false
	}
	l.zl.Error().Err(err).Send()
	return true
}

func (l Logger) WithFields(fields map[string]interface{}) Logger {
	return Logger{l.zl.With().Fields(fields).Logger()}
}

func (l Logger) MsgWithFields(fields map[string]interface{}, msg string) {
	l.logEvent().Fields(fields).Msg(msg)
}

func (l Logger) logEvent() *zerolog.Event {
	return l.zl.WithLevel(l.zl.GetLevel())
}
