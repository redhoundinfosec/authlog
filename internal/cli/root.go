// Package cli implements the command-line interface for authlog.
package cli

import (
	"flag"
	"fmt"
	"os"

	"github.com/redhoundinfosec/authlog/internal/output"
)

const usageText = `authlog - Authentication log analyzer and triage tool

Usage:
  authlog <command> [flags] [arguments]

Commands:
  analyze    Parse and summarize authentication events from one or more log files
  version    Print version information

Examples:
  authlog analyze auth.log
  authlog analyze auth.log --format json
  authlog analyze auth.log windows.xml --since 2026-04-01 --until 2026-04-03
  authlog analyze auth.log --threshold 3 --top 20 --verbose
  authlog analyze auth.log --format csv -o report.csv

Run 'authlog <command> --help' for command-specific flags.
`

// Run is the main entry point for the CLI. It returns an exit code.
func Run(args []string) int {
	if len(args) < 1 {
		fmt.Fprint(os.Stderr, usageText)
		return 2
	}

	switch args[0] {
	case "analyze":
		return runAnalyze(args[1:])
	case "version":
		fmt.Printf("authlog v%s\n", output.Version)
		return 0
	case "--help", "-h", "help":
		fmt.Print(usageText)
		return 0
	default:
		fmt.Fprintf(os.Stderr, "unknown command: %s\n\n%s", args[0], usageText)
		return 2
	}
}

// newFlagSet creates a flag.FlagSet with standard error handling and usage.
func newFlagSet(name string, usage string) *flag.FlagSet {
	fs := flag.NewFlagSet(name, flag.ContinueOnError)
	fs.Usage = func() {
		fmt.Fprint(os.Stderr, usage)
		fs.PrintDefaults()
		fmt.Fprintln(os.Stderr)
	}
	return fs
}
