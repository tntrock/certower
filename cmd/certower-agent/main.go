// Command certower-agent runs on hosts, generates keys locally, and installs
// certificates pushed by the Certower server.
package main

import (
	"fmt"
	"os"

	"github.com/tntrock/certower/internal/version"
)

func main() {
	if len(os.Args) < 2 {
		usage()
		os.Exit(2)
	}
	switch os.Args[1] {
	case "enroll", "run":
		fmt.Fprintf(os.Stderr, "certower-agent %s: not implemented yet\n", os.Args[1])
		os.Exit(1)
	case "version":
		fmt.Printf("certower-agent %s (%s)\n", version.Version, version.Commit)
	default:
		usage()
		os.Exit(2)
	}
}

func usage() {
	fmt.Fprintln(os.Stderr, `usage: certower-agent <command> [flags]

commands:
  enroll    register with a server using a one-time token
  run       connect to the server and process work
  version   print version`)
}
