// Command authlog is a CLI tool for analyzing authentication logs from
// Linux (auth.log/secure) and Windows (Security Event XML/JSON) sources.
//
// Usage:
//
//	authlog analyze <logfile> [flags]
//	authlog version
package main

import (
	"os"

	"github.com/redhoundinfosec/authlog/internal/cli"
)

func main() {
	os.Exit(cli.Run(os.Args[1:]))
}
