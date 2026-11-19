package api

import (
	"net/http"
	"net/netip"
	"strings"
	"sync"
	"time"
)

// loginLimiter throttles password guessing. It counts failed logins per
// account and per source address in a sliding window; once either reaches
// its limit, logins for that account or from that address are refused until
// the oldest counted failure leaves the window. A successful login clears
// the account's count.
//
// State is kept in memory, so each server process counts on its own.
type loginLimiter struct {
	window     time.Duration
	perAccount int
	perAddress int
	now        func() time.Time

	mu    sync.Mutex
	fails map[string][]time.Time
}

const maxLimiterKeys = 100_000

func newLoginLimiter() *loginLimiter {
	return &loginLimiter{
		window:     15 * time.Minute,
		perAccount: 10,
		perAddress: 30,
		now:        time.Now,
		fails:      map[string][]time.Time{},
	}
}

func accountKey(email string) string { return "a:" + email }

// addressKey groups IPv6 clients by /64, the block one subscriber usually
// controls.
func addressKey(ip string) string {
	addr, err := netip.ParseAddr(ip)
	if err != nil {
		return "ip:" + ip
	}
	addr = addr.Unmap()
	if addr.Is6() {
		p, _ := addr.Prefix(64)
		return "ip:" + p.String()
	}
	return "ip:" + addr.String()
}

// recent drops failures older than the window. Callers hold mu.
func (l *loginLimiter) recent(key string, now time.Time) []time.Time {
	ts := l.fails[key]
	i := 0
	for i < len(ts) && now.Sub(ts[i]) >= l.window {
		i++
	}
	ts = ts[i:]
	if len(ts) == 0 {
		delete(l.fails, key)
		return nil
	}
	l.fails[key] = ts
	return ts
}

// check reports how long the caller must wait, or 0 if it may try.
func (l *loginLimiter) check(email, ip string) time.Duration {
	l.mu.Lock()
	defer l.mu.Unlock()
	now := l.now()
	var wait time.Duration
	for key, limit := range map[string]int{accountKey(email): l.perAccount, addressKey(ip): l.perAddress} {
		ts := l.recent(key, now)
		if len(ts) >= limit {
			// Allowed again once enough failures have aged out.
			if w := ts[len(ts)-limit].Add(l.window).Sub(now); w > wait {
				wait = w
			}
		}
	}
	return wait
}

func (l *loginLimiter) fail(email, ip string) {
	l.mu.Lock()
	defer l.mu.Unlock()
	now := l.now()
	if len(l.fails) >= maxLimiterKeys {
		for key := range l.fails {
			l.recent(key, now)
		}
	}
	for key, limit := range map[string]int{accountKey(email): l.perAccount, addressKey(ip): l.perAddress} {
		ts := append(l.recent(key, now), now)
		if len(ts) > limit {
			ts = ts[len(ts)-limit:]
		}
		l.fails[key] = ts
	}
}

func (l *loginLimiter) succeed(email string) {
	l.mu.Lock()
	defer l.mu.Unlock()
	delete(l.fails, accountKey(email))
}

// ParseTrustedProxies parses a comma-separated list of addresses and CIDR
// prefixes.
func ParseTrustedProxies(s string) ([]netip.Prefix, error) {
	var out []netip.Prefix
	for _, f := range strings.Split(s, ",") {
		f = strings.TrimSpace(f)
		if f == "" {
			continue
		}
		if strings.Contains(f, "/") {
			p, err := netip.ParsePrefix(f)
			if err != nil {
				return nil, err
			}
			out = append(out, p.Masked())
			continue
		}
		a, err := netip.ParseAddr(f)
		if err != nil {
			return nil, err
		}
		out = append(out, netip.PrefixFrom(a.Unmap(), a.Unmap().BitLen()))
	}
	return out, nil
}

func (s *Server) trusted(a netip.Addr) bool {
	for _, p := range s.TrustedProxies {
		if p.Contains(a) {
			return true
		}
	}
	return false
}

// clientIP is the TCP peer, or, when the peer is a trusted proxy, the
// nearest untrusted address in X-Forwarded-For.
func (s *Server) clientIP(r *http.Request) string {
	ap, err := netip.ParseAddrPort(r.RemoteAddr)
	if err != nil {
		return ""
	}
	peer := ap.Addr().Unmap()
	if !s.trusted(peer) {
		return peer.String()
	}
	hops := strings.Split(strings.Join(r.Header.Values("X-Forwarded-For"), ","), ",")
	for i := len(hops) - 1; i >= 0; i-- {
		a, err := netip.ParseAddr(strings.TrimSpace(hops[i]))
		if err != nil {
			break // a malformed hop could be forged; stop at the last good one
		}
		peer = a.Unmap()
		if !s.trusted(peer) {
			break
		}
	}
	return peer.String()
}
