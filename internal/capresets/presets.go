// Package capresets lists known ACME CAs. Presets are data, not code: when
// a CA changes its endpoint, only this table changes.
package capresets

// Preset pre-fills the generic ACME issuer for a known CA.
type Preset struct {
	ID   string `json:"id"`
	Name string `json:"name"`
	// DirectoryURL is the ACME directory. Empty means the CA issues a
	// per-account URL and the user must paste it in.
	DirectoryURL string `json:"directoryUrl"`
	RequiresEAB  bool   `json:"requiresEab"`
	DocsURL      string `json:"docsUrl"`
	Notes        string `json:"notes,omitempty"`
}

// All returns the built-in presets. See docs/ca-support.md.
func All() []Preset {
	return []Preset{
		{
			ID:           "letsencrypt",
			Name:         "Let's Encrypt",
			DirectoryURL: "https://acme-v02.api.letsencrypt.org/directory",
			DocsURL:      "https://letsencrypt.org/docs/",
		},
		{
			ID:           "letsencrypt-staging",
			Name:         "Let's Encrypt (staging)",
			DirectoryURL: "https://acme-staging-v02.api.letsencrypt.org/directory",
			DocsURL:      "https://letsencrypt.org/docs/staging-environment/",
			Notes:        "Untrusted test certificates with high rate limits.",
		},
		{
			ID:           "zerossl",
			Name:         "ZeroSSL",
			DirectoryURL: "https://acme.zerossl.com/v2/DV90",
			RequiresEAB:  true,
			DocsURL:      "https://zerossl.com/documentation/acme/",
		},
		{
			ID:           "google",
			Name:         "Google Trust Services",
			DirectoryURL: "https://dv.acme-v02.api.pki.goog/directory",
			RequiresEAB:  true,
			DocsURL:      "https://pki.goog/",
		},
		{
			ID:           "sectigo-dv",
			Name:         "Sectigo (DV)",
			DirectoryURL: "https://acme.sectigo.com/v2/DV",
			RequiresEAB:  true,
			DocsURL:      "https://www.sectigo.com/",
		},
		{
			ID:          "globalsign",
			Name:        "GlobalSign Atlas",
			RequiresEAB: true,
			DocsURL:     "https://docs.globalsign.com/solutions/services/clm/acme",
			Notes:       "Copy the directory URL and EAB from your Atlas account.",
		},
		{
			ID:          "digicert",
			Name:        "DigiCert",
			RequiresEAB: true,
			DocsURL:     "https://dev.digicert.com/certcentral-apis/services-api/api-keys/acme-external-account-binding-new.html",
			Notes:       "The legacy CertCentral ACME endpoint was retired on 2026-02-24; use the URL from your current account.",
		},
		{
			ID:          "twca",
			Name:        "TWCA 臺灣網路認證",
			RequiresEAB: true,
			DocsURL:     "https://www.twca.com.tw/",
			Notes:       "Request the ACME directory URL and EAB from TWCA (MSSL 2.0 program).",
		},
	}
}

// Get returns the preset with the given ID.
func Get(id string) (Preset, bool) {
	for _, p := range All() {
		if p.ID == id {
			return p, true
		}
	}
	return Preset{}, false
}
