// Package agent is certower-agent: it enrolls with a server, keeps the
// private keys of its certificates on the host, and installs issued
// certificates into local services.
package agent

import (
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"runtime"
	"slices"
	"strings"
)

// Config is the agent's local configuration, stored as agent.json in the
// state directory. The allow-lists are the host's own limits on what the
// server may make the agent do: edit them on the host, not from the server.
type Config struct {
	Server   string `json:"server"`
	AgentID  string `json:"agentId"`
	CASHA256 string `json:"caSha256"`

	// AllowedPaths are directories certificates and keys may be written
	// under.
	AllowedPaths []string `json:"allowedPaths"`
	// AllowedCommands are the exact commands (program and arguments) the
	// server may ask the agent to run to test or reload a service.
	AllowedCommands [][]string `json:"allowedCommands"`
}

// DefaultAllowedPaths is where certificates may be written unless the
// operator says otherwise.
func DefaultAllowedPaths() []string {
	if runtime.GOOS == "windows" {
		base := os.Getenv("ProgramData")
		if base == "" {
			base = `C:\ProgramData`
		}
		return []string{filepath.Join(base, "Certower", "certs")}
	}
	return []string{"/etc/certower"}
}

// DefaultAllowedCommands covers testing and reloading common web servers.
func DefaultAllowedCommands() [][]string {
	return [][]string{
		{"nginx", "-t"},
		{"nginx", "-s", "reload"},
		{"systemctl", "reload", "nginx"},
		{"apachectl", "-t"},
		{"apachectl", "graceful"},
		{"systemctl", "reload", "apache2"},
		{"systemctl", "reload", "httpd"},
	}
}

func configPath(stateDir string) string { return filepath.Join(stateDir, "agent.json") }

// LoadConfig reads agent.json.
func LoadConfig(stateDir string) (*Config, error) {
	b, err := os.ReadFile(configPath(stateDir))
	if errors.Is(err, os.ErrNotExist) {
		return nil, fmt.Errorf("agent is not enrolled (no %s); run \"certower-agent enroll\" first", configPath(stateDir))
	} else if err != nil {
		return nil, err
	}
	var c Config
	if err := json.Unmarshal(b, &c); err != nil {
		return nil, fmt.Errorf("%s: %w", configPath(stateDir), err)
	}
	return &c, nil
}

func (c *Config) save(stateDir string) error {
	b, err := json.MarshalIndent(c, "", "  ")
	if err != nil {
		return err
	}
	return writeFileAtomic(configPath(stateDir), append(b, '\n'), 0o600)
}

// commandAllowed reports whether cmd is exactly one of the allowed commands.
func (c *Config) commandAllowed(cmd []string) bool {
	for _, allowed := range c.AllowedCommands {
		if slices.Equal(allowed, cmd) {
			return true
		}
	}
	return false
}

// pathAllowed reports whether path lies inside an allowed directory, after
// resolving symbolic links in its parent so a link cannot point outside.
func (c *Config) pathAllowed(path string) error {
	if !filepath.IsAbs(path) {
		return fmt.Errorf("%s: path must be absolute", path)
	}
	clean := filepath.Clean(path)
	resolved := clean
	if dir, err := filepath.EvalSymlinks(filepath.Dir(clean)); err == nil {
		resolved = filepath.Join(dir, filepath.Base(clean))
	}
	for _, root := range c.AllowedPaths {
		root = filepath.Clean(root)
		rootResolved := root
		if r, err := filepath.EvalSymlinks(root); err == nil {
			rootResolved = r
		}
		if within(clean, root) && within(resolved, rootResolved) {
			return nil
		}
	}
	return fmt.Errorf("%s is outside the allowed directories %v (edit allowedPaths in agent.json to change)", path, c.AllowedPaths)
}

func within(path, root string) bool {
	if runtime.GOOS == "windows" {
		path, root = strings.ToLower(path), strings.ToLower(root)
	}
	rel, err := filepath.Rel(root, path)
	return err == nil && rel != "." && !strings.HasPrefix(rel, "..") && !filepath.IsAbs(rel)
}
