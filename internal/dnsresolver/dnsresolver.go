// Package dnsresolver chooses the DNS servers used for ACME DNS-01 zone
// lookups and propagation checks.
//
// lego keeps these in process-wide state and, on systems without
// /etc/resolv.conf (Windows), falls back to Google Public DNS, which many
// corporate and campus networks block. Configure replaces that with the
// operating system's resolvers, ordered by responsiveness, and detects
// networks where authoritative name servers cannot be reached directly.
package dnsresolver

import (
	"fmt"
	"log/slog"
	"net"
	"sort"
	"sync"
	"time"

	"github.com/go-acme/lego/v4/challenge/dns01"
	"github.com/miekg/dns"
)

// Mode says whether propagation is checked against the zone's
// authoritative name servers or only through the recursive resolvers.
type Mode string

const (
	// ModeAuto checks directly whether authoritative servers are reachable.
	ModeAuto Mode = "auto"
	// ModeAuthoritative checks the zone's authoritative servers (lego's
	// default, most accurate).
	ModeAuthoritative Mode = "authoritative"
	// ModeRecursiveOnly checks only through the configured resolvers, for
	// networks that block outbound DNS except to internal resolvers.
	ModeRecursiveOnly Mode = "recursive"
)

// Settings is the result of Configure.
type Settings struct {
	Servers       []string // host:port, responsive ones only, fastest first
	RecursiveOnly bool
}

var (
	mu      sync.RWMutex
	current Settings
)

// probeTimeout bounds each reachability probe.
var probeTimeout = 2 * time.Second

// rootServer is a.root-servers.net, used to test direct access to
// authoritative servers.
const rootServer = "198.41.0.4:53"

// Configure sets the resolvers for the whole process. With no servers it
// uses the operating system's. It must be called before issuing.
func Configure(servers []string, mode Mode, log *slog.Logger) (Settings, error) {
	if log == nil {
		log = slog.Default()
	}
	if len(servers) == 0 {
		sys, err := System()
		if err != nil {
			return Settings{}, fmt.Errorf("dnsresolver: read system resolvers: %w", err)
		}
		servers = sys
	}
	servers = dns01.ParseNameservers(servers)
	if len(servers) == 0 {
		return Settings{}, fmt.Errorf("dnsresolver: no DNS servers found; set them explicitly")
	}

	// lego asks every server in turn when a name has no answer, so a dead
	// server costs a full timeout on each lookup. Leave unresponsive
	// servers out unless none respond.
	alive, dead := rank(servers)
	if len(alive) == 0 {
		alive = servers
		log.Warn("no DNS server answered a probe; using all of them", "servers", servers)
	} else if len(dead) > 0 {
		log.Warn("DNS servers did not answer a probe and will not be used", "servers", dead)
	}

	s := Settings{Servers: alive}
	switch mode {
	case ModeRecursiveOnly:
		s.RecursiveOnly = true
	case ModeAuthoritative:
	case ModeAuto, "":
		if !answers(rootServer) {
			s.RecursiveOnly = true
			log.Info("authoritative DNS servers are unreachable from this network; checking propagation through resolvers only")
		}
	default:
		return Settings{}, fmt.Errorf("dnsresolver: unknown mode %q", mode)
	}

	// The option only assigns lego's package variable; the Challenge
	// argument is unused.
	if err := dns01.AddRecursiveNameservers(s.Servers)(nil); err != nil {
		return Settings{}, err
	}
	mu.Lock()
	current = s
	mu.Unlock()
	return s, nil
}

// ChallengeOptions returns the lego options that apply the settings to one
// DNS-01 challenge.
func ChallengeOptions() []dns01.ChallengeOption {
	mu.RLock()
	defer mu.RUnlock()
	if current.RecursiveOnly {
		return []dns01.ChallengeOption{dns01.DisableAuthoritativeNssPropagationRequirement()}
	}
	return nil
}

// Current returns the active settings.
func Current() Settings {
	mu.RLock()
	defer mu.RUnlock()
	return current
}

// rank probes servers concurrently and returns responsive ones fastest
// first, then the unresponsive ones in their original order.
func rank(servers []string) (alive, dead []string) {
	type result struct {
		i   int
		rtt time.Duration
		ok  bool
	}
	results := make([]result, len(servers))
	var wg sync.WaitGroup
	for i, s := range servers {
		wg.Add(1)
		go func() {
			defer wg.Done()
			start := time.Now()
			ok := answers(s)
			results[i] = result{i, time.Since(start), ok}
		}()
	}
	wg.Wait()
	sort.SliceStable(results, func(a, b int) bool {
		if results[a].ok != results[b].ok {
			return results[a].ok
		}
		if results[a].ok {
			return results[a].rtt < results[b].rtt
		}
		return results[a].i < results[b].i
	})
	for _, r := range results {
		if r.ok {
			alive = append(alive, servers[r.i])
		} else {
			dead = append(dead, servers[r.i])
		}
	}
	return alive, dead
}

// answers reports whether server responds to a query for the root zone.
func answers(server string) bool {
	m := new(dns.Msg)
	m.SetQuestion(".", dns.TypeNS)
	m.RecursionDesired = false
	c := &dns.Client{Timeout: probeTimeout}
	in, _, err := c.Exchange(m, server)
	return err == nil && in != nil
}

// isUsable filters out addresses that are never real resolvers.
func isUsable(ip net.IP) bool {
	if ip == nil || ip.IsUnspecified() || ip.IsLinkLocalUnicast() {
		return false
	}
	// Windows lists fec0:0:0:ffff::1-3 when no IPv6 DNS is configured.
	if ip.To4() == nil && ip[0] == 0xfe && ip[1]&0xc0 == 0xc0 {
		return false
	}
	return true
}
