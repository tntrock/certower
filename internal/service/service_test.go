package service

import (
	"os"
	"path/filepath"
	"slices"
	"testing"
)

func TestConfigArg(t *testing.T) {
	t.Setenv("CERTOWER_CONFIG", "")
	for _, c := range []struct {
		in   []string
		path string
		rest []string
	}{
		{[]string{"-listen", ":1"}, "", []string{"-listen", ":1"}},
		{[]string{"-config", "a.env", "-listen", ":1"}, "a.env", []string{"-listen", ":1"}},
		{[]string{"--config=b.env"}, "b.env", nil},
		{[]string{"-listen", ":1", "-config=c.env"}, "c.env", []string{"-listen", ":1"}},
		{[]string{"-configure"}, "", []string{"-configure"}},
	} {
		path, rest := ConfigArg(c.in)
		if path != c.path || !slices.Equal(rest, c.rest) {
			t.Errorf("ConfigArg(%q) = %q %q, want %q %q", c.in, path, rest, c.path, c.rest)
		}
	}
	t.Setenv("CERTOWER_CONFIG", "env.env")
	if path, _ := ConfigArg(nil); path != "env.env" {
		t.Errorf("CERTOWER_CONFIG ignored: %q", path)
	}
}

func TestLoadEnvFile(t *testing.T) {
	p := filepath.Join(t.TempDir(), "certower.env")
	os.WriteFile(p, []byte(`# comment

CERTOWER_TEST_A=plain
export CERTOWER_TEST_B="quoted value"
CERTOWER_TEST_C='single'
CERTOWER_TEST_D=from file
CERTOWER_TEST_E=C:/ProgramData/Certower/certower.db
`), 0o600)
	for _, k := range []string{"A", "B", "C", "E"} {
		t.Setenv("CERTOWER_TEST_"+k, "")
		os.Unsetenv("CERTOWER_TEST_" + k)
	}
	t.Setenv("CERTOWER_TEST_D", "from environment")
	if err := LoadEnvFile(p); err != nil {
		t.Fatal(err)
	}
	for k, want := range map[string]string{
		"A": "plain", "B": "quoted value", "C": "single", "D": "from environment",
		"E": "C:/ProgramData/Certower/certower.db",
	} {
		if got := os.Getenv("CERTOWER_TEST_" + k); got != want {
			t.Errorf("%s = %q, want %q", k, got, want)
		}
	}

	bad := filepath.Join(t.TempDir(), "bad.env")
	os.WriteFile(bad, []byte("no equals sign\n"), 0o600)
	if err := LoadEnvFile(bad); err == nil {
		t.Error("malformed line accepted")
	}
}
