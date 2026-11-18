package dnsresolver

import (
	"net"
	"testing"
	"time"

	"github.com/miekg/dns"
)

// fakeDNS answers every query after delay and returns its address.
func fakeDNS(t *testing.T, delay time.Duration) string {
	t.Helper()
	pc, err := net.ListenPacket("udp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	srv := &dns.Server{PacketConn: pc, Handler: dns.HandlerFunc(func(w dns.ResponseWriter, r *dns.Msg) {
		time.Sleep(delay)
		m := new(dns.Msg)
		m.SetReply(r)
		w.WriteMsg(m)
	})}
	go srv.ActivateAndServe()
	t.Cleanup(func() { srv.Shutdown() })
	return pc.LocalAddr().String()
}

// deadAddr returns a UDP address nothing answers on.
func deadAddr(t *testing.T) string {
	t.Helper()
	pc, err := net.ListenPacket("udp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	addr := pc.LocalAddr().String()
	pc.Close()
	return addr
}

func TestRank(t *testing.T) {
	probeTimeout = 300 * time.Millisecond
	slow := fakeDNS(t, 100*time.Millisecond)
	fast := fakeDNS(t, 0)
	dead := deadAddr(t)

	alive, gone := rank([]string{dead, slow, fast})
	if len(alive) != 2 || alive[0] != fast || alive[1] != slow {
		t.Errorf("alive = %v, want [%s %s]", alive, fast, slow)
	}
	if len(gone) != 1 || gone[0] != dead {
		t.Errorf("dead = %v, want [%s]", gone, dead)
	}
}

func TestConfigure(t *testing.T) {
	probeTimeout = 300 * time.Millisecond
	fast := fakeDNS(t, 0)
	dead := deadAddr(t)

	s, err := Configure([]string{dead, fast}, ModeRecursiveOnly, nil)
	if err != nil {
		t.Fatal(err)
	}
	if len(s.Servers) != 1 || s.Servers[0] != fast || !s.RecursiveOnly || len(ChallengeOptions()) != 1 {
		t.Errorf("settings = %+v, options = %d", s, len(ChallengeOptions()))
	}
	s, err = Configure([]string{fast}, ModeAuthoritative, nil)
	if err != nil || s.RecursiveOnly || len(ChallengeOptions()) != 0 {
		t.Errorf("authoritative mode: %+v, %v", s, err)
	}
	if _, err := Configure([]string{fast}, "bogus", nil); err == nil {
		t.Error("unknown mode accepted")
	}
}

func TestSystem(t *testing.T) {
	servers, err := System()
	if err != nil {
		t.Skipf("no system resolvers: %v", err)
	}
	for _, s := range servers {
		if _, _, err := net.SplitHostPort(s); err != nil {
			t.Errorf("%q is not host:port", s)
		}
	}
	t.Logf("system resolvers: %v", servers)
}

func TestIsUsable(t *testing.T) {
	for addr, want := range map[string]bool{
		"192.0.2.53":       true,
		"2001:db8::53":     true,
		"0.0.0.0":          false,
		"fe80::1":          false,
		"fec0:0:0:ffff::1": false,
	} {
		if got := isUsable(net.ParseIP(addr)); got != want {
			t.Errorf("isUsable(%s) = %v, want %v", addr, got, want)
		}
	}
}
