// Copyright 2026 The go-remotesigner Authors.
// SPDX-License-Identifier: Apache-2.0

// Package logging sets up the process logger: logrus with its own
// TextFormatter or JSONFormatter, the Web3Signer --logging level names, an
// optional log file, and a hook that redacts secret-bearing fields.
package logging

import (
	"errors"
	"fmt"
	"io"
	"os"
	"slices"
	"strings"

	"github.com/sirupsen/logrus"
)

// Formats accepted by --logging-format.
const (
	FormatText = "text"
	FormatJSON = "json"
)

// Levels are the --logging values, as Web3Signer names them.
var Levels = []string{"OFF", "FATAL", "ERROR", "WARN", "INFO", "DEBUG", "TRACE", "ALL"}

// ErrInvalid reports a bad level or format.
var ErrInvalid = errors.New("logging: invalid setting")

// Config is the logging configuration.
type Config struct {
	Level  string // one of Levels, case-insensitive
	Format string // FormatText or FormatJSON
	File   string // log to this file instead of stderr when set
}

// Validate checks the level and format.
func (c Config) Validate() error {
	if _, _, err := parseLevel(c.Level); err != nil {
		return err
	}
	if _, err := formatter(c.Format); err != nil {
		return err
	}
	return nil
}

// New returns a logger for cfg that writes to stderr, or to cfg.File when
// it is set. The returned closer closes the file; it is a no-op otherwise.
func New(cfg Config, stderr io.Writer) (*logrus.Logger, io.Closer, error) {
	level, off, err := parseLevel(cfg.Level)
	if err != nil {
		return nil, nil, err
	}
	f, err := formatter(cfg.Format)
	if err != nil {
		return nil, nil, err
	}
	out, closer := stderr, io.Closer(nopCloser{})
	if cfg.File != "" {
		file, err := os.OpenFile(cfg.File, os.O_WRONLY|os.O_CREATE|os.O_APPEND, 0o600)
		if err != nil {
			return nil, nil, fmt.Errorf("logging: open log file: %w", err)
		}
		out, closer = file, file
	}
	if off {
		out = io.Discard
	}
	log := logrus.New()
	log.SetOutput(out)
	log.SetLevel(level)
	log.SetFormatter(f)
	log.AddHook(RedactHook{})
	return log, closer, nil
}

// parseLevel maps a Web3Signer level name to a logrus level. OFF discards all
// output; ALL is logrus's most verbose level.
func parseLevel(s string) (level logrus.Level, off bool, err error) {
	switch strings.ToUpper(s) {
	case "OFF":
		return logrus.PanicLevel, true, nil
	case "FATAL":
		return logrus.FatalLevel, false, nil
	case "ERROR":
		return logrus.ErrorLevel, false, nil
	case "WARN":
		return logrus.WarnLevel, false, nil
	case "INFO":
		return logrus.InfoLevel, false, nil
	case "DEBUG":
		return logrus.DebugLevel, false, nil
	case "TRACE", "ALL":
		return logrus.TraceLevel, false, nil
	}
	return 0, false, fmt.Errorf("%w: level %q (want one of %s)", ErrInvalid, s, strings.Join(Levels, ", "))
}

func formatter(s string) (logrus.Formatter, error) {
	switch strings.ToLower(s) {
	case FormatText:
		return &logrus.TextFormatter{FullTimestamp: true, DisableColors: true}, nil
	case FormatJSON:
		return &logrus.JSONFormatter{}, nil
	}
	return nil, fmt.Errorf("%w: format %q (want %s or %s)", ErrInvalid, s, FormatText, FormatJSON)
}

type nopCloser struct{}

func (nopCloser) Close() error { return nil }

// Redacted is what a redacted value is replaced with.
const Redacted = "[REDACTED]"

// redactedFields are the field names whose values are never logged,
// compared case-insensitively.
var redactedFields = []string{"password", "passwords", "keystores", "authorization", "cookie", "token", "secret"}

// RedactHook replaces the value of every field named in redactedFields with
// Redacted before the entry is formatted.
type RedactHook struct{}

// Levels returns every level.
func (RedactHook) Levels() []logrus.Level { return logrus.AllLevels }

// Fire redacts e's fields in place.
func (RedactHook) Fire(e *logrus.Entry) error {
	for k := range e.Data {
		if slices.Contains(redactedFields, strings.ToLower(k)) {
			e.Data[k] = Redacted
		}
	}
	return nil
}
