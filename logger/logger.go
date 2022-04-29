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
	l.zl.WithLevel(l.zl.GetLevel()).Msgf(format, a...)
}

func (l Logger) Msg(msg string) {
	l.zl.WithLevel(l.zl.GetLevel()).Msg(msg)
}

func (l Logger) Err(err error) {
	l.zl.Error().Err(err).Send()
}

func (l Logger) WithFields(fields map[string]interface{}) Logger {
	return Logger{l.zl.With().Fields(fields).Logger()}
}

func (l Logger) MsgWithFields(fields map[string]interface{}, msg string) {
	l.zl.Log().Fields(fields).Msg(msg)
}
