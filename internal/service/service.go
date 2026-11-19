// Package service helps Certower's commands run as long-lived services:
// under systemd, in a container, or as a Windows service, with settings
// from an environment file.
package service

import (
	"bufio"
	"fmt"
	"io"
	"log/slog"
	"os"
	"strings"
)

// ConfigArg removes "-config <path>" or "-config=<path>" (one or two
// dashes) from args and returns the path, or CERTOWER_CONFIG if the flag
// is absent. It runs before flag parsing because flag defaults are read
// from the environment the file sets.
func ConfigArg(args []string) (path string, rest []string) {
	path = os.Getenv("CERTOWER_CONFIG")
	for i := 0; i < len(args); i++ {
		a := args[i]
		name, value, hasValue := strings.Cut(strings.TrimLeft(a, "-"), "=")
		if !strings.HasPrefix(a, "-") || name != "config" {
			rest = append(rest, a)
			continue
		}
		if hasValue {
			path = value
		} else if i+1 < len(args) {
			path = args[i+1]
			i++
		}
	}
	return path, rest
}

// LoadEnvFile sets environment variables from a file of KEY=VALUE lines.
// Blank lines and lines starting with # are ignored, and values may be
// quoted. Variables already in the environment win, so "docker run -e" or
// a systemd override still applies.
func LoadEnvFile(path string) error {
	f, err := os.Open(path)
	if err != nil {
		return err
	}
	defer f.Close()
	sc := bufio.NewScanner(f)
	for n := 1; sc.Scan(); n++ {
		line := strings.TrimSpace(sc.Text())
		if line == "" || strings.HasPrefix(line, "#") {
			continue
		}
		key, value, ok := strings.Cut(strings.TrimPrefix(line, "export "), "=")
		key = strings.TrimSpace(key)
		if !ok || key == "" {
			return fmt.Errorf("%s:%d: want KEY=VALUE", path, n)
		}
		value = strings.TrimSpace(value)
		if len(value) >= 2 && (value[0] == '"' || value[0] == '\'') && value[len(value)-1] == value[0] {
			value = value[1 : len(value)-1]
		}
		if _, set := os.LookupEnv(key); !set {
			os.Setenv(key, value)
		}
	}
	return sc.Err()
}

// Logger returns a text logger on stderr, or appending to file when set.
// A Windows service has no console, so it needs a file.
func Logger(file string) (*slog.Logger, io.Closer, error) {
	if file == "" {
		return slog.New(slog.NewTextHandler(os.Stderr, nil)), io.NopCloser(nil), nil
	}
	f, err := os.OpenFile(file, os.O_CREATE|os.O_WRONLY|os.O_APPEND, 0o640)
	if err != nil {
		return nil, nil, err
	}
	return slog.New(slog.NewTextHandler(f, nil)), f, nil
}
