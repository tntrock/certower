package plugin

// DNSSolver solves ACME DNS-01 challenges.
//
// The method set matches lego's challenge.Provider, so any of lego's DNS
// providers can be wrapped without adaptation.
type DNSSolver interface {
	Plugin
	Present(domain, token, keyAuth string) error
	CleanUp(domain, token, keyAuth string) error
}
