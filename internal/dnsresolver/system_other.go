//go:build !windows

package dnsresolver

import (
	"net"

	"github.com/miekg/dns"
)

// System returns the nameservers from /etc/resolv.conf.
func System() ([]string, error) {
	cfg, err := dns.ClientConfigFromFile("/etc/resolv.conf")
	if err != nil {
		return nil, err
	}
	var out []string
	for _, s := range cfg.Servers {
		if isUsable(net.ParseIP(s)) {
			out = append(out, net.JoinHostPort(s, cfg.Port))
		}
	}
	return out, nil
}
