// Package all registers every built-in plugin with plugin.Default.
package all

import (
	_ "github.com/tntrock/certower/internal/plugins/acme"
	_ "github.com/tntrock/certower/internal/plugins/cloudflare"
)
