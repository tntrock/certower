package discovery

import (
	"context"
	"crypto/tls"
	"crypto/x509"
	"errors"
	"fmt"
	"net"
	"strconv"
	"time"
)

// More finding codes, from the trust check.
const (
	CodeUntrusted        = "untrusted"
	CodeHostnameMismatch = "hostname_mismatch"
)

// Scanner fetches the certificate chain a TLS endpoint serves.
type Scanner struct {
	// Timeout bounds each scan. Default 10s.
	Timeout time.Duration
	// Roots verify chains; nil means the system roots.
	Roots *x509.CertPool
	// AllowLinkLocal permits link-local addresses such as the cloud
	// metadata service 169.254.169.254, which are refused by default so
	// discovery cannot be used to probe them.
	AllowLinkLocal bool
	// Resolver looks up hostnames; nil means net.DefaultResolver.
	Resolver *net.Resolver
}

// ErrBlockedAddress is returned for addresses the scanner refuses.
var ErrBlockedAddress = errors.New("address not allowed for scanning")

// Result is what a scan found.
type Result struct {
	Chain    []*x509.Certificate
	Findings []Finding
	// Address is the IP and port actually connected to.
	Address string
}

// Scan connects to host:port, sending sni (default: host when it is a
// name), and checks the chain it gets.
func (s *Scanner) Scan(ctx context.Context, host string, port int, sni string, opt Options) (*Result, error) {
	timeout := s.Timeout
	if timeout <= 0 {
		timeout = 10 * time.Second
	}
	ctx, cancel := context.WithTimeout(ctx, timeout)
	defer cancel()

	if sni == "" && net.ParseIP(host) == nil {
		sni = host
	}
	ip, err := s.resolve(ctx, host)
	if err != nil {
		return nil, err
	}
	addr := net.JoinHostPort(ip.String(), strconv.Itoa(port))
	// Connect to the vetted IP, not the name, so a second DNS answer
	// cannot redirect the connection.
	d := &tls.Dialer{Config: &tls.Config{ServerName: sni, InsecureSkipVerify: true}}
	conn, err := d.DialContext(ctx, "tcp", addr)
	if err != nil {
		return nil, err
	}
	defer conn.Close()
	chain := conn.(*tls.Conn).ConnectionState().PeerCertificates
	if len(chain) == 0 {
		return nil, errors.New("server sent no certificate")
	}

	fs := Check(chain, opt)
	if f := s.trust(chain, sni, opt.Now); f != nil {
		fs = append(fs, *f)
	}
	return &Result{Chain: chain, Findings: fs, Address: addr}, nil
}

func (s *Scanner) resolve(ctx context.Context, host string) (net.IP, error) {
	var ips []net.IP
	if ip := net.ParseIP(host); ip != nil {
		ips = []net.IP{ip}
	} else {
		r := s.Resolver
		if r == nil {
			r = net.DefaultResolver
		}
		addrs, err := r.LookupIPAddr(ctx, host)
		if err != nil {
			return nil, err
		}
		for _, a := range addrs {
			ips = append(ips, a.IP)
		}
	}
	if len(ips) == 0 {
		return nil, fmt.Errorf("%s has no addresses", host)
	}
	// Refuse if any address is blocked, so a name cannot mix an allowed
	// and a blocked address.
	for _, ip := range ips {
		if ip.IsUnspecified() || ip.IsMulticast() || (!s.AllowLinkLocal && (ip.IsLinkLocalUnicast() || ip.IsLinkLocalMulticast())) {
			return nil, fmt.Errorf("%w: %s resolves to %s", ErrBlockedAddress, host, ip)
		}
	}
	return ips[0], nil
}

// trust verifies the chain the way a browser would.
func (s *Scanner) trust(chain []*x509.Certificate, sni string, now time.Time) *Finding {
	inter := x509.NewCertPool()
	for _, c := range chain[1:] {
		inter.AddCert(c)
	}
	opts := x509.VerifyOptions{Roots: s.Roots, Intermediates: inter, DNSName: sni, CurrentTime: now}
	_, err := chain[0].Verify(opts)
	if err == nil {
		return nil
	}
	var host x509.HostnameError
	if errors.As(err, &host) {
		return &Finding{CodeHostnameMismatch, Critical, fmt.Sprintf("certificate is not valid for %q", sni)}
	}
	var inv x509.CertificateInvalidError
	if errors.As(err, &inv) && inv.Reason == x509.Expired {
		return nil // already reported as expired
	}
	return &Finding{CodeUntrusted, Warning, "chain does not lead to a trusted root: " + err.Error()}
}
