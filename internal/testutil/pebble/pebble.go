// Package pebble runs Pebble, Let's Encrypt's ACME test server, and its mock
// DNS server for integration tests. Install the binaries with
//
//	go install github.com/letsencrypt/pebble/v2/cmd/pebble@latest
//	go install github.com/letsencrypt/pebble/v2/cmd/pebble-challtestsrv@latest
//
// Tests should skip when Start returns an error.
package pebble

import (
	"bytes"
	"context"
	"embed"
	"encoding/json"
	"fmt"
	"net"
	"net/http"
	"os"
	"os/exec"
	"path/filepath"
	"sync/atomic"
	"time"

	"github.com/go-acme/lego/v4/challenge/dns01"

	"github.com/tntrock/certower/pkg/plugin"
)

const (
	// EABKeyID and EABHMAC are accepted by the EAB-requiring instance.
	EABKeyID = "kid-1"
	EABHMAC  = "zWNDZM6eQGHWpSRTPal5eIUYFTu7EajVIoguysqZ9wG44nMEtx3MUAsUDkMTQ12W"

	// ShortLived is the lifetime of the "shortlived" profile. The
	// "default" profile issues 90-day certificates.
	ShortLived = 6 * 24 * time.Hour
)

//go:embed certs/*.pem certs/*.key
var certs embed.FS

// Env describes running Pebble instances. Every Start uses its own free
// ports, so test packages running in parallel do not collide.
type Env struct {
	PlainURL string // directory URL; no EAB required
	EABURL   string // directory URL; EAB required
	Roots    string // PEM to trust for Pebble's HTTPS
	// DNSAddr is the mock DNS server, the only one that knows challenge
	// records. Point the DNS resolvers at it.
	DNSAddr string

	challMgmt string
}

// freePorts reserves n distinct local TCP ports. The mock DNS server also
// binds UDP on its port, which is free whenever the TCP port is.
func freePorts(n int) ([]int, error) {
	var ls []net.Listener
	defer func() {
		for _, l := range ls {
			l.Close()
		}
	}()
	var ports []int
	for len(ports) < n {
		l, err := net.Listen("tcp", "127.0.0.1:0")
		if err != nil {
			return nil, err
		}
		ls = append(ls, l)
		ports = append(ports, l.Addr().(*net.TCPAddr).Port)
	}
	return ports, nil
}

// Start launches the mock DNS server and two Pebble instances. Call the
// returned function to stop them.
func Start() (*Env, func(), error) {
	pebbleBin, err := findBinary("pebble")
	if err != nil {
		return nil, nil, err
	}
	challBin, err := findBinary("pebble-challtestsrv")
	if err != nil {
		return nil, nil, err
	}
	dir, err := os.MkdirTemp("", "certower-pebble")
	if err != nil {
		return nil, nil, err
	}
	var procs []*exec.Cmd
	stop := func() {
		for _, p := range procs {
			p.Process.Kill()
			p.Wait()
		}
		os.RemoveAll(dir)
	}
	fail := func(err error) (*Env, func(), error) {
		stop()
		return nil, nil, err
	}

	for _, name := range []string{"pebble-localhost.pem", "pebble-localhost.key", "pebble-minica.pem"} {
		b, err := certs.ReadFile("certs/" + name)
		if err != nil {
			return fail(err)
		}
		if err := os.WriteFile(filepath.Join(dir, name), b, 0o600); err != nil {
			return fail(err)
		}
	}

	start := func(bin string, args ...string) error {
		cmd := exec.Command(bin, args...)
		cmd.Env = append(os.Environ(), "PEBBLE_VA_NOSLEEP=1", "PEBBLE_WFE_NONCEREJECT=0")
		cmd.Dir = dir
		if err := cmd.Start(); err != nil {
			return err
		}
		procs = append(procs, cmd)
		return nil
	}
	writeConfig := func(name, listen, mgmt string, eab bool) (string, error) {
		pc := map[string]any{
			"listenAddress":           listen,
			"managementListenAddress": mgmt,
			"certificate":             filepath.Join(dir, "pebble-localhost.pem"),
			"privateKey":              filepath.Join(dir, "pebble-localhost.key"),
			"httpPort":                5002,
			"tlsPort":                 5001,
			"profiles": map[string]any{
				"default":    map[string]any{"description": "default", "validityPeriod": 90 * 24 * 3600},
				"shortlived": map[string]any{"description": "short", "validityPeriod": int(ShortLived.Seconds())},
			},
		}
		if eab {
			pc["externalAccountBindingRequired"] = true
			pc["externalAccountMACKeys"] = map[string]string{EABKeyID: EABHMAC}
		}
		b, _ := json.Marshal(map[string]any{"pebble": pc})
		path := filepath.Join(dir, name)
		return path, os.WriteFile(path, b, 0o600)
	}

	ports, err := freePorts(6)
	if err != nil {
		return fail(err)
	}
	addr := func(i int) string { return fmt.Sprintf("127.0.0.1:%d", ports[i]) }
	env := &Env{
		PlainURL:  "https://" + addr(2) + "/dir",
		EABURL:    "https://" + addr(4) + "/dir",
		DNSAddr:   addr(0),
		challMgmt: addr(1),
	}

	if err := start(challBin, "-dnsserver", env.DNSAddr, "-management", env.challMgmt,
		"-http01", "", "-https01", "", "-tlsalpn01", "", "-doh", ""); err != nil {
		return fail(err)
	}
	plain, err := writeConfig("plain.json", addr(2), addr(3), false)
	if err != nil {
		return fail(err)
	}
	withEAB, err := writeConfig("eab.json", addr(4), addr(5), true)
	if err != nil {
		return fail(err)
	}
	for _, cfg := range []string{plain, withEAB} {
		if err := start(pebbleBin, "-config", cfg, "-dnsserver", env.DNSAddr); err != nil {
			return fail(err)
		}
	}
	for _, a := range []string{env.challMgmt, addr(2), addr(4)} {
		if err := waitListening(a); err != nil {
			return fail(err)
		}
	}
	roots, err := certs.ReadFile("certs/pebble-minica.pem")
	if err != nil {
		return fail(err)
	}
	env.Roots = string(roots)
	return env, stop, nil
}

func findBinary(name string) (string, error) {
	if p, err := exec.LookPath(name); err == nil {
		return p, nil
	}
	if gopath, err := exec.Command("go", "env", "GOPATH").Output(); err == nil {
		p := filepath.Join(string(bytes.TrimSpace(gopath)), "bin", name)
		if _, err := exec.LookPath(p); err == nil {
			return p, nil
		}
	}
	return "", fmt.Errorf("%s not found", name)
}

func waitListening(addr string) error {
	deadline := time.Now().Add(15 * time.Second)
	for time.Now().Before(deadline) {
		if c, err := net.Dial("tcp", addr); err == nil {
			c.Close()
			return nil
		}
		time.Sleep(100 * time.Millisecond)
	}
	return fmt.Errorf("%s did not start listening", addr)
}

// ChallDNS is a DNS plugin that writes TXT records into this Env's mock DNS
// server. Register it with Env.ChallDNSFactory.
type ChallDNS struct {
	mgmt      string
	presented atomic.Int32
}

// NewChallDNS returns a ChallDNS bound to the Env's mock DNS server.
func (e *Env) NewChallDNS() *ChallDNS { return &ChallDNS{mgmt: e.challMgmt} }

// ChallDNSFactory is a plugin.Factory for the "pebble-dns" plugin.
func (e *Env) ChallDNSFactory() plugin.Factory {
	return func() plugin.Plugin { return e.NewChallDNS() }
}

func (c *ChallDNS) Meta() plugin.Meta {
	return plugin.Meta{Name: "pebble-dns", Kind: plugin.KindDNS, ConfigSchema: json.RawMessage(`{"type":"object"}`)}
}

func (c *ChallDNS) Configure(context.Context, json.RawMessage) error { return nil }

func (c *ChallDNS) Present(domain, token, keyAuth string) error {
	info := dns01.GetChallengeInfo(domain, keyAuth)
	c.presented.Add(1)
	return c.post("/set-txt", map[string]string{"host": info.EffectiveFQDN, "value": info.Value})
}

func (c *ChallDNS) CleanUp(domain, token, keyAuth string) error {
	info := dns01.GetChallengeInfo(domain, keyAuth)
	return c.post("/clear-txt", map[string]string{"host": info.EffectiveFQDN})
}

// Presented counts Present calls.
func (c *ChallDNS) Presented() int { return int(c.presented.Load()) }

func (c *ChallDNS) post(path string, body any) error {
	b, _ := json.Marshal(body)
	resp, err := http.Post("http://"+c.mgmt+path, "application/json", bytes.NewReader(b))
	if err != nil {
		return err
	}
	resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		return fmt.Errorf("challtestsrv %s: %s", path, resp.Status)
	}
	return nil
}
