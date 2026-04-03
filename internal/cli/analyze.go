package cli

import (
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"time"

	"github.com/redhoundinfosec/authlog/internal/analyzer"
	"github.com/redhoundinfosec/authlog/internal/output"
	"github.com/redhoundinfosec/authlog/internal/parser"
)

const analyzeUsage = `Usage: authlog analyze [flags] <logfile> [logfile2 ...]

Parse and summarize authentication events from one or more log files.
Formats are auto-detected: Linux auth.log/secure, Windows Event XML, Windows Event JSON.

Flags:
`

func runAnalyze(args []string) int {
	fs := newFlagSet("analyze", analyzeUsage)

	var (
		format    = fs.String("format", "text", "Output format: text, json, csv")
		fmtShort  = fs.String("f", "text", "Output format (shorthand)")
		outFile   = fs.String("output", "", "Write output to file")
		outShort  = fs.String("o", "", "Write output to file (shorthand)")
		since     = fs.String("since", "", "Start time filter (RFC3339 or YYYY-MM-DD)")
		until     = fs.String("until", "", "End time filter (RFC3339 or YYYY-MM-DD)")
		top       = fs.Int("top", 10, "Number of top entries to show")
		threshold = fs.Int("threshold", 5, "Brute force threshold: N failures in 5 minutes")
		noColor   = fs.Bool("no-color", false, "Disable colored output")
		quiet     = fs.Bool("quiet", false, "Summary line only")
		qShort    = fs.Bool("q", false, "Summary line only (shorthand)")
		verbose   = fs.Bool("verbose", false, "Show individual events")
		vShort    = fs.Bool("v", false, "Show individual events (shorthand)")
	)

	// Go's flag package stops at the first non-flag argument. To support
	// mixed positional and flag arguments (e.g. "analyze file.log --no-color"),
	// we separate files from flags before parsing.
	flagArgs, fileArgs := splitFlagsAndFiles(args)

	if err := fs.Parse(flagArgs); err != nil {
		// flag.ErrHelp is returned when -h/--help is passed
		fmt.Fprintf(os.Stderr, "error: %v\n", err)
		return 2
	}

	// Merge remaining positional args from the flag parser with pre-separated file args
	files := append(fileArgs, fs.Args()...)
	if len(files) == 0 {
		fmt.Fprintln(os.Stderr, "error: at least one log file is required")
		fmt.Fprintf(os.Stderr, analyzeUsage)
		fs.PrintDefaults()
		return 2
	}

	// Resolve shorthand flags
	outFmt := *format
	if *fmtShort != "text" && outFmt == "text" {
		outFmt = *fmtShort
	}
	outPath := *outFile
	if *outShort != "" && outPath == "" {
		outPath = *outShort
	}
	isQuiet := *quiet || *qShort
	isVerbose := *verbose || *vShort

	// Parse time filters
	sinceTime, err := parseTimeFlag(*since)
	if err != nil {
		fmt.Fprintf(os.Stderr, "error parsing --since: %v\n", err)
		return 2
	}
	untilTime, err := parseTimeFlag(*until)
	if err != nil {
		fmt.Fprintf(os.Stderr, "error parsing --until: %v\n", err)
		return 2
	}

	// Read and parse all files
	var allEvents []*parser.AuthEvent
	var sources []string
	formatsSeen := make(map[string]bool)

	for _, fpath := range files {
		data, err := os.ReadFile(fpath)
		if err != nil {
			fmt.Fprintf(os.Stderr, "error reading %s: %v\n", fpath, err)
			return 2
		}

		events, fmt_, err := parser.AutoParse(data)
		if err != nil {
			fmt.Fprintf(os.Stderr, "error parsing %s: %v\n", fpath, err)
			return 2
		}
		if fmt_ == parser.FormatUnknown {
			fmt.Fprintf(os.Stderr, "warning: could not detect format of %s, skipping\n", fpath)
			continue
		}

		allEvents = append(allEvents, events...)
		sources = append(sources, filepath.Base(fpath))
		formatsSeen[string(fmt_)] = true
	}

	var fmtList []string
	for k := range formatsSeen {
		fmtList = append(fmtList, k)
	}

	// Build analysis config
	cfg := analyzer.Config{
		Since: sinceTime,
		Until: untilTime,
		TopN:  *top,
		BruteForce: analyzer.BruteForceConfig{
			Threshold: *threshold,
			Window:    5 * time.Minute,
		},
	}

	report := analyzer.Analyze(allEvents, sources, fmtList, cfg)

	// Determine output writer
	w := os.Stdout
	if outPath != "" {
		f, err := os.Create(outPath)
		if err != nil {
			fmt.Fprintf(os.Stderr, "error creating output file: %v\n", err)
			return 2
		}
		defer f.Close()
		w = f
	}

	// Render
	opts := output.Options{
		Format:  output.Format(outFmt),
		NoColor: *noColor,
		Quiet:   isQuiet,
		Verbose: isVerbose,
	}

	if err := output.Render(w, report, opts); err != nil {
		fmt.Fprintf(os.Stderr, "error rendering output: %v\n", err)
		return 2
	}

	// Exit code
	if report.Suspicious {
		return 1
	}
	return 0
}

// parseTimeFlag parses a time string in RFC3339 or YYYY-MM-DD format.
func parseTimeFlag(s string) (time.Time, error) {
	if s == "" {
		return time.Time{}, nil
	}
	s = strings.TrimSpace(s)

	formats := []string{
		time.RFC3339,
		"2006-01-02T15:04:05",
		"2006-01-02 15:04:05",
		"2006-01-02",
	}
	for _, f := range formats {
		if t, err := time.Parse(f, s); err == nil {
			return t, nil
		}
	}
	return time.Time{}, fmt.Errorf("cannot parse %q as time (use RFC3339 or YYYY-MM-DD)", s)
}

// splitFlagsAndFiles separates a mixed args slice into flag arguments
// (starting with "-" or "--") and non-flag positional file arguments.
// Flag arguments that take values (e.g. --format json) are kept together.
// This allows the user to place file arguments before, after, or between flags.
func splitFlagsAndFiles(args []string) (flagArgs []string, fileArgs []string) {
	// Flags that consume the next argument as their value
	valueFlags := map[string]bool{
		"-format": true, "--format": true,
		"-f":      true, // -f is also a value flag
		"-output": true, "--output": true,
		"-o":      true,
		"-since":  true, "--since":  true,
		"-until":  true, "--until":  true,
		"-top":    true, "--top":    true,
		"-threshold": true, "--threshold": true,
	}

	i := 0
	for i < len(args) {
		arg := args[i]
		if strings.HasPrefix(arg, "-") {
			// Check if it contains "=" (e.g. --format=json)
			if strings.Contains(arg, "=") {
				flagArgs = append(flagArgs, arg)
				i++
				continue
			}
			// Check if this flag takes a value argument
			if valueFlags[arg] && i+1 < len(args) && !strings.HasPrefix(args[i+1], "-") {
				flagArgs = append(flagArgs, arg, args[i+1])
				i += 2
			} else {
				flagArgs = append(flagArgs, arg)
				i++
			}
		} else {
			fileArgs = append(fileArgs, arg)
			i++
		}
	}
	return
}
