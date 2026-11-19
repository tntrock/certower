package api

import (
	"net/http"
	"net/http/httptest"
	"testing"
	"time"
)

func TestLoginLimiter(t *testing.T) {
	now := time.Date(2026, 1, 1, 0, 0, 0, 0, time.UTC)
	l := newLoginLimiter()
	l.now = func() time.Time { return now }

	for i := 0; i < l.perAccount; i++ {
		if w := l.check("a@example.com", "192.0.2.1"); w != 0 {
			t.Fatalf("attempt %d blocked", i)
		}
		l.fail("a@example.com", "192.0.2.1")
		now = now.Add(time.Second)
	}
	if w := l.check("a@example.com", "198.51.100.7"); w <= 0 || w > l.window {
		t.Fatalf("account not blocked from another address: %v", w)
	}
	if w := l.check("b@example.com", "192.0.2.1"); w != 0 {
		t.Fatalf("other account blocked: %v", w)
	}
	// The first failure ages out of the window, allowing one more try.
	now = now.Add(l.window - time.Duration(l.perAccount)*time.Second + time.Second)
	if w := l.check("a@example.com", "192.0.2.1"); w != 0 {
		t.Fatalf("still blocked after window: %v", w)
	}

	// A success clears the account but not the address.
	l.succeed("a@example.com")
	if l.fails[accountKey("a@example.com")] != nil {
		t.Fatal("account count not cleared")
	}

	// Address limit, with IPv6 grouped by /64.
	for i := 0; i < l.perAddress; i++ {
		l.fail("user"+string(rune('a'+i%26))+"@example.com", "2001:db8::1")
	}
	if w := l.check("new@example.com", "2001:db8::ffff"); w == 0 {
		t.Fatal("same /64 not blocked")
	}
	if w := l.check("new@example.com", "2001:db8:0:1::1"); w != 0 {
		t.Fatal("other /64 blocked")
	}
}

func TestClientIP(t *testing.T) {
	proxies, err := ParseTrustedProxies("10.0.0.0/8, 192.0.2.10")
	if err != nil {
		t.Fatal(err)
	}
	s := &Server{TrustedProxies: proxies}
	for _, c := range []struct{ peer, xff, want string }{
		{"203.0.113.5:1234", "198.51.100.1", "203.0.113.5"},                    // untrusted peer: header ignored
		{"10.1.2.3:1234", "198.51.100.1", "198.51.100.1"},                      // trusted proxy
		{"10.1.2.3:1234", "6.6.6.6, 198.51.100.1, 192.0.2.10", "198.51.100.1"}, // chain, spoofed first hop ignored
		{"10.1.2.3:1234", "", "10.1.2.3"},
		{"10.1.2.3:1234", "junk", "10.1.2.3"},
		{"[::ffff:10.1.2.3]:1234", "198.51.100.1", "198.51.100.1"},
	} {
		r := httptest.NewRequest(http.MethodGet, "/", nil)
		r.RemoteAddr = c.peer
		if c.xff != "" {
			r.Header.Set("X-Forwarded-For", c.xff)
		}
		if got := s.clientIP(r); got != c.want {
			t.Errorf("peer %s xff %q: got %s, want %s", c.peer, c.xff, got, c.want)
		}
	}
	if _, err := ParseTrustedProxies("10.0.0.0/33"); err == nil {
		t.Error("bad prefix accepted")
	}
}

func TestLoginRateLimited(t *testing.T) {
	e := newEnv(t)
	e.user("admin@example.com", true)
	for i := 0; i < 10; i++ {
		e.do("", "POST", "/api/v1/auth/login", loginRequest{Email: "admin@example.com", Password: "wrong password!!"}, 401, nil)
	}
	// Even the right password is refused while blocked.
	e.do("", "POST", "/api/v1/auth/login", loginRequest{Email: "Admin@Example.com", Password: "long enough password"}, 429, nil)
}
