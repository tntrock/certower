package agentproto

import (
	"crypto/sha256"
	"crypto/tls"
	"crypto/x509"
	"encoding/hex"
	"errors"
	"fmt"
)

func fingerprint(der []byte) string {
	h := sha256.Sum256(der)
	return hex.EncodeToString(h[:])
}

// PinnedClientConfig returns a TLS client configuration that trusts only
// a server whose chain leads to the CA with the given SHA-256 fingerprint.
// It is what agents use; hostnames are not checked.
func PinnedClientConfig(caSHA256 string) *tls.Config {
	want := normalizeFP(caSHA256)
	return &tls.Config{
		MinVersion:         tls.VersionTLS12,
		InsecureSkipVerify: true, // replaced by VerifyPeerCertificate below
		VerifyPeerCertificate: func(raw [][]byte, _ [][]*x509.Certificate) error {
			if len(raw) < 2 {
				return errors.New("agentproto: server sent no CA certificate")
			}
			certs := make([]*x509.Certificate, len(raw))
			for i, r := range raw {
				c, err := x509.ParseCertificate(r)
				if err != nil {
					return err
				}
				certs[i] = c
			}
			root := certs[len(certs)-1]
			if fp := fingerprint(root.Raw); fp != want {
				return fmt.Errorf("agentproto: server CA fingerprint %s does not match the pinned %s", fp, want)
			}
			pool := x509.NewCertPool()
			pool.AddCert(root)
			inter := x509.NewCertPool()
			for _, c := range certs[1 : len(certs)-1] {
				inter.AddCert(c)
			}
			_, err := certs[0].Verify(x509.VerifyOptions{Roots: pool, Intermediates: inter,
				KeyUsages: []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth}})
			return err
		},
	}
}

// normalizeFP accepts hex with or without colons, any case.
func normalizeFP(s string) string {
	out := make([]byte, 0, len(s))
	for i := 0; i < len(s); i++ {
		ch := s[i]
		switch {
		case ch == ':' || ch == ' ':
		case ch >= 'A' && ch <= 'F':
			out = append(out, ch+'a'-'A')
		default:
			out = append(out, ch)
		}
	}
	return string(out)
}
