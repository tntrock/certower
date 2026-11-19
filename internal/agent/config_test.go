package agent

import (
	"os"
	"path/filepath"
	"runtime"
	"testing"
)

func TestPathAllowed(t *testing.T) {
	root := t.TempDir()
	allowed := filepath.Join(root, "certs")
	os.MkdirAll(allowed, 0o755)
	c := &Config{AllowedPaths: []string{allowed}}

	ok := []string{
		filepath.Join(allowed, "a.pem"),
		filepath.Join(allowed, "site", "key.pem"),
	}
	bad := []string{
		allowed, // the directory itself
		filepath.Join(allowed, "..", "escape.pem"),
		filepath.Join(root, "certs-other", "a.pem"), // prefix trick
		"relative/a.pem",
	}
	for _, p := range ok {
		if err := c.pathAllowed(p); err != nil {
			t.Errorf("%s refused: %v", p, err)
		}
	}
	for _, p := range bad {
		if err := c.pathAllowed(p); err == nil {
			t.Errorf("%s allowed", p)
		}
	}

	// A symlink inside the allowed directory must not lead outside it.
	outside := filepath.Join(root, "outside")
	os.MkdirAll(outside, 0o755)
	link := filepath.Join(allowed, "link")
	if err := os.Symlink(outside, link); err != nil {
		if runtime.GOOS == "windows" {
			t.Skip("creating symlinks needs privileges on Windows")
		}
		t.Fatal(err)
	}
	if err := c.pathAllowed(filepath.Join(link, "a.pem")); err == nil {
		t.Error("path through a symlink to outside was allowed")
	}
}

func TestCommandAllowed(t *testing.T) {
	c := &Config{AllowedCommands: DefaultAllowedCommands()}
	if !c.commandAllowed([]string{"nginx", "-s", "reload"}) {
		t.Error("default nginx reload refused")
	}
	for _, cmd := range [][]string{
		{"nginx", "-s", "reload", ";", "rm", "-rf", "/"},
		{"nginx"},
		{"sh", "-c", "nginx -s reload"},
	} {
		if c.commandAllowed(cmd) {
			t.Errorf("%q allowed", cmd)
		}
	}
}

func TestResolveSettings(t *testing.T) {
	s, err := ResolveSettings("nginx", []byte(`{"fullchainPath":"/etc/certower/f.pem","keyPath":"/etc/certower/k.pem"}`))
	if err != nil {
		t.Fatal(err)
	}
	if s.VerifyEndpoint != "127.0.0.1:443" || len(s.ReloadCommand) == 0 || len(s.TestCommand) == 0 {
		t.Errorf("nginx defaults not applied: %+v", s)
	}
	for name, raw := range map[string]string{
		"no key":        `{"fullchainPath":"/x"}`,
		"unknown field": `{"fullchainPath":"/x","keyPath":"/y","shell":"bash"}`,
		"bad endpoint":  `{"certPath":"/x","keyPath":"/y","verifyEndpoint":"nohost"}`,
		"files no cert": `{"keyPath":"/y"}`,
	} {
		deployer := "files"
		if _, err := ResolveSettings(deployer, []byte(raw)); err == nil {
			t.Errorf("%s: accepted", name)
		}
	}
	if _, err := ResolveSettings("ftp", []byte(`{}`)); err == nil {
		t.Error("unknown deployer accepted")
	}
}
