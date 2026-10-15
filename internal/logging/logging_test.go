// Copyright 2026 The go-remotesigner Authors.
// SPDX-License-Identifier: Apache-2.0

package logging

import (
	"bytes"
	"encoding/json"
	"errors"
	"fmt"
	"log/slog"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/sirupsen/logrus"
)

func TestLevels(t *testing.T) {
	tests := []struct {
		name string
		want logrus.Level
		off  bool
	}{
		{"OFF", logrus.PanicLevel, true},
		{"fatal", logrus.FatalLevel, false},
		{"ERROR", logrus.ErrorLevel, false},
		{"WARN", logrus.WarnLevel, false},
		{"info", logrus.InfoLevel, false},
		{"DEBUG", logrus.DebugLevel, false},
		{"TRACE", logrus.TraceLevel, false},
		{"ALL", logrus.TraceLevel, false},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got, off, err := parseLevel(tt.name)
			if err != nil || got != tt.want || off != tt.off {
				t.Fatalf("parseLevel(%q) = %v, %v, %v; want %v, %v, nil", tt.name, got, off, err, tt.want, tt.off)
			}
		})
	}
	if _, _, err := parseLevel("VERBOSE"); !errors.Is(err, ErrInvalid) {
		t.Fatalf("parseLevel(VERBOSE) error = %v, want ErrInvalid", err)
	}
}

func TestValidate(t *testing.T) {
	tests := []struct {
		cfg   Config
		valid bool
	}{
		{Config{Level: "INFO", Format: "text"}, true},
		{Config{Level: "ALL", Format: "JSON"}, true},
		{Config{Level: "LOUD", Format: "text"}, false},
		{Config{Level: "INFO", Format: "plain"}, false},
	}
	for _, tt := range tests {
		if err := tt.cfg.Validate(); (err == nil) != tt.valid {
			t.Errorf("%+v.Validate() = %v, want valid %v", tt.cfg, err, tt.valid)
		}
	}
}

func TestNewFormatsAndRedacts(t *testing.T) {
	var buf bytes.Buffer
	log, closer, err := New(Config{Level: "INFO", Format: FormatJSON}, &buf)
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = closer.Close() }()

	log.WithFields(logrus.Fields{
		"Authorization": "Bearer 0xsecret",
		"token":         "0xsecret",
		"password":      "hunter2",
		"path":          "/data/auth-token",
	}).Info("hello")
	log.Debug("not shown at INFO")

	var got map[string]any
	if err := json.Unmarshal(buf.Bytes(), &got); err != nil {
		t.Fatalf("output %q is not one JSON object: %v", buf.String(), err)
	}
	for _, k := range []string{"Authorization", "token", "password"} {
		if got[k] != Redacted {
			t.Errorf("field %s = %v, want %s", k, got[k], Redacted)
		}
	}
	if got["path"] != "/data/auth-token" {
		t.Errorf("field path = %v, want it unredacted", got["path"])
	}
	if strings.Contains(buf.String(), "secret") || strings.Contains(buf.String(), "hunter2") {
		t.Errorf("output leaks a secret: %s", buf.String())
	}
}

func TestNewOffAndFile(t *testing.T) {
	var buf bytes.Buffer
	log, closer, err := New(Config{Level: "OFF", Format: FormatText}, &buf)
	if err != nil {
		t.Fatal(err)
	}
	log.Error("dropped")
	_ = closer.Close()
	if buf.Len() != 0 {
		t.Errorf("OFF wrote %q", buf.String())
	}

	path := filepath.Join(t.TempDir(), "signer.log")
	log, closer, err = New(Config{Level: "INFO", Format: FormatText, File: path}, &buf)
	if err != nil {
		t.Fatal(err)
	}
	log.Info("to file")
	if err := closer.Close(); err != nil {
		t.Fatal(err)
	}
	data, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(string(data), "to file") || buf.Len() != 0 {
		t.Errorf("file = %q, stderr = %q; want the line in the file only", data, buf.String())
	}
}

func TestSecret(t *testing.T) {
	s := Secret("0xdeadbeef")
	for _, got := range []string{
		s.String(), fmt.Sprint(s), fmt.Sprintf("%v %s %#v", s, s, s), s.LogValue().String(),
	} {
		if strings.Contains(got, "deadbeef") {
			t.Errorf("formatted secret %q leaks the value", got)
		}
	}
	if _, err := json.Marshal(struct{ S Secret }{s}); err == nil {
		t.Error("json.Marshal of a Secret succeeded")
	}
	var buf bytes.Buffer
	slog.New(slog.NewTextHandler(&buf, nil)).Info("x", "token", s)
	if strings.Contains(buf.String(), "deadbeef") {
		t.Errorf("slog leaks the secret: %s", buf.String())
	}
}
