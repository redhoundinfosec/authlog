// Package output renders analysis reports in text, JSON, and CSV formats.
package output

import (
	"encoding/csv"
	"encoding/json"
	"fmt"
	"io"
	"strings"
	"time"

	"github.com/redhoundinfosec/authlog/internal/analyzer"
	"github.com/redhoundinfosec/authlog/internal/parser"
)

// Version is injected at build time via -ldflags.
var Version = "0.1.0"

// Format specifies the output format.
type Format string

const (
	FormatText Format = "text"
	FormatJSON Format = "json"
	FormatCSV  Format = "csv"
)

// Options controls output rendering.
type Options struct {
	Format  Format
	NoColor bool
	Quiet   bool    // summary line only
	Verbose bool    // show individual events
}

// --- ANSI color codes ---
const (
	colorReset  = "\033[0m"
	colorRed    = "\033[31m"
	colorYellow = "\033[33m"
	colorGreen  = "\033[32m"
	colorCyan   = "\033[36m"
	colorWhite  = "\033[37m"
	colorBold   = "\033[1m"
	colorDim    = "\033[2m"
	colorBoldRed = "\033[1;31m"
	colorBoldYellow = "\033[1;33m"
	colorBoldGreen  = "\033[1;32m"
	colorBoldCyan   = "\033[1;36m"
)

// Render writes the report to w in the specified format.
func Render(w io.Writer, r *analyzer.Report, opts Options) error {
	switch opts.Format {
	case FormatJSON:
		return renderJSON(w, r)
	case FormatCSV:
		return renderCSV(w, r)
	default:
		return renderText(w, r, opts)
	}
}

// ─────────────────────────────────────────────
// TEXT RENDERER
// ─────────────────────────────────────────────

func renderText(w io.Writer, r *analyzer.Report, opts Options) error {
	c := &colorizer{enabled: !opts.NoColor}

	// Header
	fmt.Fprintf(w, "\n%s\n", c.bold(fmt.Sprintf("authlog v%s — Authentication Log Analysis", Version)))
	fmt.Fprintln(w)

	// Source info
	for _, src := range r.Sources {
		fmt.Fprintf(w, "  %s %s\n", c.dim("Source:"), src)
	}
	if len(r.Formats) > 0 {
		fmt.Fprintf(w, "  %s %s\n", c.dim("Format:"), strings.Join(r.Formats, ", "))
	}
	if !r.FirstEvent.IsZero() {
		fmt.Fprintf(w, "  %s %s → %s\n",
			c.dim("Period:"),
			r.FirstEvent.UTC().Format("2006-01-02 15:04:05"),
			r.LastEvent.UTC().Format("2006-01-02 15:04:05"),
		)
	}
	fmt.Fprintf(w, "  %s %d\n", c.dim("Total Events:"), r.TotalEvents)
	fmt.Fprintln(w)

	if opts.Quiet {
		verdict := "CLEAN"
		if r.Suspicious {
			verdict = "SUSPICIOUS"
		}
		fmt.Fprintf(w, "Verdict: %s | Events: %d | Failures: %d | Successes: %d | BruteForce: %d\n",
			verdict, r.TotalEvents, r.FailedLogins, r.SuccessfulLogins, len(r.BruteForce))
		return nil
	}

	// Event summary
	fmt.Fprintf(w, "  %s\n", c.bold("EVENT SUMMARY"))
	fmt.Fprintf(w, "  ├─ %-28s %s\n", "Successful logins", c.green(fmt.Sprintf("%d", r.SuccessfulLogins)))
	fmt.Fprintf(w, "  ├─ %-28s %s\n", "Failed logins", c.red(fmt.Sprintf("%d", r.FailedLogins)))
	fmt.Fprintf(w, "  ├─ %-28s %d\n", "Privilege escalation", r.PrivilegeEscs)
	if r.AccountsCreated > 0 {
		fmt.Fprintf(w, "  ├─ %-28s %s\n", "Accounts created", c.yellow(fmt.Sprintf("%d", r.AccountsCreated)))
	}
	if r.GroupChanges > 0 {
		fmt.Fprintf(w, "  ├─ %-28s %s\n", "Group membership changes", c.yellow(fmt.Sprintf("%d", r.GroupChanges)))
	}
	fmt.Fprintf(w, "  └─ %-28s %d\n", "Other", r.OtherEvents+r.Disconnects)
	fmt.Fprintln(w)

	// Brute force section
	if len(r.BruteForce) > 0 {
		fmt.Fprintf(w, "  %s\n", c.boldYellow("⚠ BRUTE FORCE DETECTED"))
		for _, bf := range r.BruteForce {
			users := strings.Join(bf.TargetUsernames, ", ")
			if len(users) > 60 {
				users = users[:57] + "..."
			}
			dur := formatDuration(bf.Window)
			fmt.Fprintf(w, "  %s %s → %d failures in %s targeting: %s\n",
				c.yellow("●"), bf.SourceIP, bf.FailureCount, dur, users)
			if bf.FollowedBySuccess && bf.SuccessEvent != nil {
				sev := bf.SuccessEvent
				fmt.Fprintf(w, "    %s %s\n",
					c.boldRed("└─ FOLLOWED BY successful login as "+sev.Username+
						" at "+sev.Timestamp.UTC().Format("15:04:05")),
					c.boldRed("[CRITICAL]"),
				)
			}
		}
		fmt.Fprintln(w)
	}

	// Top failed login sources
	if len(r.TopFailedSources) > 0 {
		fmt.Fprintf(w, "  %s\n", c.bold("TOP FAILED LOGIN SOURCES"))
		for i, e := range r.TopFailedSources {
			fmt.Fprintf(w, "  %2d. %-20s %s\n",
				i+1, e.Name, c.red(fmt.Sprintf("%d failures", e.Count)))
		}
		fmt.Fprintln(w)
	}

	// Top targeted accounts
	if len(r.TopTargetAccounts) > 0 {
		fmt.Fprintf(w, "  %s\n", c.bold("TOP TARGETED ACCOUNTS"))
		for i, e := range r.TopTargetAccounts {
			fmt.Fprintf(w, "  %2d. %-20s %s\n",
				i+1, e.Name, c.red(fmt.Sprintf("%d failures", e.Count)))
		}
		fmt.Fprintln(w)
	}

	// Privilege escalation
	if len(r.PrivEscEvents) > 0 {
		fmt.Fprintf(w, "  %s\n", c.bold("PRIVILEGE ESCALATION"))
		for i, pe := range r.PrivEscEvents {
			connector := "├─"
			if i == len(r.PrivEscEvents)-1 {
				connector = "└─"
			}
			ts := pe.Timestamp.UTC().Format("15:04:05")
			msg := pe.Message
			if msg == "" && pe.Command != "" {
				msg = pe.Command
			}
			// Collapse multiline privilege lists (Windows 4672 events) to single line
			msg = strings.ReplaceAll(msg, "\n", ", ")
			if pe.Sensitive {
				fmt.Fprintf(w, "  %s %s: %s (%s)  %s\n",
					connector, pe.Username, msg, ts, c.yellow("[WARNING]"))
			} else {
				fmt.Fprintf(w, "  %s %s: %s (%s)\n", connector, pe.Username, msg, ts)
			}
		}
		fmt.Fprintln(w)
	}

	// Account creation / group changes
	if r.AccountsCreated > 0 || r.GroupChanges > 0 {
		fmt.Fprintf(w, "  %s\n", c.bold("NOTABLE EVENTS"))
		for _, ev := range r.Events {
			if ev.Type == parser.EventAccountCreated || ev.Type == parser.EventGroupChange {
				ts := ev.Timestamp.UTC().Format("15:04:05")
				fmt.Fprintf(w, "  ├─ %s %s (%s)\n", c.yellow("["+string(ev.Type)+"]"), ev.Message, ts)
			}
		}
		fmt.Fprintln(w)
	}

	// Timeline
	if r.PeakHour != "" {
		fmt.Fprintf(w, "  %s\n", c.bold("TIMELINE"))
		if len(r.Timeline) <= 10 {
			for _, b := range r.Timeline {
				bar := strings.Repeat("█", clamp(b.Count, 1, 30))
				fmt.Fprintf(w, "  %s  %s %d\n", b.Hour, c.cyan(bar), b.Count)
			}
		} else {
			fmt.Fprintf(w, "  Peak activity: %s (%d events)\n", r.PeakHour, r.PeakCount)
		}
		fmt.Fprintln(w)
	}

	// Verbose: individual events
	if opts.Verbose {
		fmt.Fprintf(w, "  %s\n", c.bold("EVENTS"))
		for _, ev := range r.Events {
			ts := ev.Timestamp.UTC().Format("2006-01-02 15:04:05")
			typ := fmt.Sprintf("%-22s", string(ev.Type))
			ip := ""
			if ev.SourceIP != "" {
				ip = " from " + ev.SourceIP
			}
			user := ""
			if ev.Username != "" {
				user = " user=" + ev.Username
			}
			fmt.Fprintf(w, "  %s  %s%s%s\n", ts, typ, user, ip)
		}
		fmt.Fprintln(w)
	}

	// Verdict
	verdictLine := ""
	if r.Suspicious {
		reasons := strings.Join(dedupStrings(r.SuspectReasons), "; ")
		verdictLine = c.boldRed(fmt.Sprintf("Verdict: SUSPICIOUS — %s", reasons))
	} else {
		verdictLine = c.boldGreen("Verdict: CLEAN — no suspicious patterns detected")
	}
	fmt.Fprintf(w, "  %s\n\n", verdictLine)

	return nil
}

// ─────────────────────────────────────────────
// JSON RENDERER
// ─────────────────────────────────────────────

type jsonReport struct {
	Version          string                `json:"version"`
	Sources          []string              `json:"sources"`
	Formats          []string              `json:"formats"`
	Period           jsonPeriod            `json:"period"`
	Summary          jsonSummary           `json:"summary"`
	TopFailedSources []jsonCountEntry      `json:"top_failed_sources"`
	TopTargetAccounts []jsonCountEntry     `json:"top_target_accounts"`
	BruteForce       []jsonBruteForce      `json:"brute_force"`
	PrivEscEvents    []jsonPrivEsc         `json:"privilege_escalation"`
	Timeline         []jsonHourBucket      `json:"timeline"`
	PeakHour         string                `json:"peak_hour"`
	Suspicious       bool                  `json:"suspicious"`
	SuspectReasons   []string              `json:"suspect_reasons"`
}

type jsonPeriod struct {
	First string `json:"first_event"`
	Last  string `json:"last_event"`
}

type jsonSummary struct {
	Total            int `json:"total_events"`
	SuccessfulLogins int `json:"successful_logins"`
	FailedLogins     int `json:"failed_logins"`
	PrivilegeEscs    int `json:"privilege_escalations"`
	AccountsCreated  int `json:"accounts_created"`
	GroupChanges     int `json:"group_changes"`
}

type jsonCountEntry struct {
	Name  string `json:"name"`
	Count int    `json:"count"`
}

type jsonBruteForce struct {
	SourceIP          string   `json:"source_ip"`
	FailureCount      int      `json:"failure_count"`
	WindowSeconds     float64  `json:"window_seconds"`
	TargetUsernames   []string `json:"target_usernames"`
	FirstSeen         string   `json:"first_seen"`
	LastSeen          string   `json:"last_seen"`
	FollowedBySuccess bool     `json:"followed_by_success"`
	SuccessUsername   string   `json:"success_username,omitempty"`
	SuccessTime       string   `json:"success_time,omitempty"`
}

type jsonPrivEsc struct {
	Timestamp string `json:"timestamp"`
	Username  string `json:"username"`
	Command   string `json:"command,omitempty"`
	Message   string `json:"message"`
	Sensitive bool   `json:"sensitive"`
}

type jsonHourBucket struct {
	Hour  string `json:"hour"`
	Count int    `json:"count"`
}

func renderJSON(w io.Writer, r *analyzer.Report) error {
	jr := jsonReport{
		Version: Version,
		Sources: r.Sources,
		Formats: r.Formats,
		Period: jsonPeriod{
			First: fmtTime(r.FirstEvent),
			Last:  fmtTime(r.LastEvent),
		},
		Summary: jsonSummary{
			Total:            r.TotalEvents,
			SuccessfulLogins: r.SuccessfulLogins,
			FailedLogins:     r.FailedLogins,
			PrivilegeEscs:    r.PrivilegeEscs,
			AccountsCreated:  r.AccountsCreated,
			GroupChanges:     r.GroupChanges,
		},
		PeakHour:       r.PeakHour,
		Suspicious:     r.Suspicious,
		SuspectReasons: dedupStrings(r.SuspectReasons),
	}

	for _, e := range r.TopFailedSources {
		jr.TopFailedSources = append(jr.TopFailedSources, jsonCountEntry{Name: e.Name, Count: e.Count})
	}
	for _, e := range r.TopTargetAccounts {
		jr.TopTargetAccounts = append(jr.TopTargetAccounts, jsonCountEntry{Name: e.Name, Count: e.Count})
	}
	for _, bf := range r.BruteForce {
		jbf := jsonBruteForce{
			SourceIP:          bf.SourceIP,
			FailureCount:      bf.FailureCount,
			WindowSeconds:     bf.Window.Seconds(),
			TargetUsernames:   bf.TargetUsernames,
			FirstSeen:         fmtTime(bf.FirstSeen),
			LastSeen:          fmtTime(bf.LastSeen),
			FollowedBySuccess: bf.FollowedBySuccess,
		}
		if bf.SuccessEvent != nil {
			jbf.SuccessUsername = bf.SuccessEvent.Username
			jbf.SuccessTime = fmtTime(bf.SuccessEvent.Timestamp)
		}
		jr.BruteForce = append(jr.BruteForce, jbf)
	}
	for _, pe := range r.PrivEscEvents {
		jr.PrivEscEvents = append(jr.PrivEscEvents, jsonPrivEsc{
			Timestamp: fmtTime(pe.Timestamp),
			Username:  pe.Username,
			Command:   pe.Command,
			Message:   pe.Message,
			Sensitive: pe.Sensitive,
		})
	}
	for _, b := range r.Timeline {
		jr.Timeline = append(jr.Timeline, jsonHourBucket{Hour: b.Hour, Count: b.Count})
	}

	enc := json.NewEncoder(w)
	enc.SetIndent("", "  ")
	return enc.Encode(jr)
}

// ─────────────────────────────────────────────
// CSV RENDERER
// ─────────────────────────────────────────────

func renderCSV(w io.Writer, r *analyzer.Report) error {
	cw := csv.NewWriter(w)

	// Header
	if err := cw.Write([]string{
		"timestamp", "event_type", "username", "source_ip", "hostname",
		"process", "message", "windows_event_id", "format",
	}); err != nil {
		return err
	}

	for _, ev := range r.Events {
		eid := ""
		if ev.WindowsEventID != 0 {
			eid = fmt.Sprintf("%d", ev.WindowsEventID)
		}
		ts := ""
		if !ev.Timestamp.IsZero() {
			ts = ev.Timestamp.UTC().Format(time.RFC3339)
		}
		if err := cw.Write([]string{
			ts,
			string(ev.Type),
			ev.Username,
			ev.SourceIP,
			ev.Hostname,
			ev.Process,
			ev.Message,
			eid,
			string(ev.Format),
		}); err != nil {
			return err
		}
	}

	cw.Flush()
	return cw.Error()
}

// ─────────────────────────────────────────────
// HELPERS
// ─────────────────────────────────────────────

func fmtTime(t time.Time) string {
	if t.IsZero() {
		return ""
	}
	return t.UTC().Format(time.RFC3339)
}

func formatDuration(d time.Duration) string {
	if d < time.Second {
		return "< 1s"
	}
	if d < time.Minute {
		return fmt.Sprintf("%ds", int(d.Seconds()))
	}
	mins := int(d.Minutes())
	secs := int(d.Seconds()) % 60
	if secs == 0 {
		return fmt.Sprintf("%dm", mins)
	}
	return fmt.Sprintf("%dm%ds", mins, secs)
}

func clamp(v, lo, hi int) int {
	if v < lo {
		return lo
	}
	if v > hi {
		return hi
	}
	return v
}

func dedupStrings(ss []string) []string {
	seen := make(map[string]bool)
	out := make([]string, 0, len(ss))
	for _, s := range ss {
		if !seen[s] {
			seen[s] = true
			out = append(out, s)
		}
	}
	return out
}

// colorizer wraps ANSI escape codes.
type colorizer struct{ enabled bool }

func (c *colorizer) wrap(code, s string) string {
	if !c.enabled {
		return s
	}
	return code + s + colorReset
}
func (c *colorizer) bold(s string) string      { return c.wrap(colorBold, s) }
func (c *colorizer) dim(s string) string       { return c.wrap(colorDim, s) }
func (c *colorizer) red(s string) string       { return c.wrap(colorRed, s) }
func (c *colorizer) green(s string) string     { return c.wrap(colorGreen, s) }
func (c *colorizer) yellow(s string) string    { return c.wrap(colorYellow, s) }
func (c *colorizer) cyan(s string) string      { return c.wrap(colorCyan, s) }
func (c *colorizer) boldRed(s string) string   { return c.wrap(colorBoldRed, s) }
func (c *colorizer) boldYellow(s string) string { return c.wrap(colorBoldYellow, s) }
func (c *colorizer) boldGreen(s string) string { return c.wrap(colorBoldGreen, s) }
