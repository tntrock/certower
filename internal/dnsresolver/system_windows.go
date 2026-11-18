package dnsresolver

import (
	"net"
	"unsafe"

	"golang.org/x/sys/windows"
)

// System returns the DNS servers of the network adapters that are up, in
// adapter order.
func System() ([]string, error) {
	size := uint32(15 * 1024)
	var buf []byte
	for {
		buf = make([]byte, size)
		err := windows.GetAdaptersAddresses(windows.AF_UNSPEC,
			windows.GAA_FLAG_SKIP_ANYCAST|windows.GAA_FLAG_SKIP_MULTICAST|windows.GAA_FLAG_SKIP_FRIENDLY_NAME,
			0, (*windows.IpAdapterAddresses)(unsafe.Pointer(&buf[0])), &size)
		if err == nil {
			break
		}
		if err != windows.ERROR_BUFFER_OVERFLOW {
			return nil, err
		}
	}

	seen := map[string]bool{}
	var out []string
	for aa := (*windows.IpAdapterAddresses)(unsafe.Pointer(&buf[0])); aa != nil; aa = aa.Next {
		if aa.OperStatus != windows.IfOperStatusUp {
			continue
		}
		for d := aa.FirstDnsServerAddress; d != nil; d = d.Next {
			ip := d.Address.IP()
			if !isUsable(ip) {
				continue
			}
			addr := net.JoinHostPort(ip.String(), "53")
			if !seen[addr] {
				seen[addr] = true
				out = append(out, addr)
			}
		}
	}
	return out, nil
}
