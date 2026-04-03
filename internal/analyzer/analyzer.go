// Package analyzer provides the core authentication log analysis engine.
package analyzer

import (
	"sort"
	"time"

	"github.com/redhoundinfosec/authlog/internal/parser"
)

// Config holds analysis configuration options.
type Config struct {
	// Since filters events to those at or after this time. Zero = no filter.
	Since time.Time

	// Until filters events to those at or before this time. Zero = no filter.
	Until time.Time

	// TopN controls how many top entries to return in ranked lists.
	TopN int

	// BruteForce is the brute force detection configuration.
	BruteForce BruteForceConfig
}

// DefaultConfig returns a Config with sensible defaults.
func DefaultConfig() Config {
	return Config{
		TopN:       10,
		BruteForce: DefaultBruteForceConfig(),
	}
}

// CountEntry is a generic name-count pair for ranking.
type CountEntry struct {
	Name  string
	Count int
}

// PrivEscEvent holds details about a single privilege escalation event.
type PrivEscEvent struct {
	Timestamp time.Time
	Username  string
	Command   string // sudo command or Windows privilege list
	Message   string
	Sensitive bool // true for commands accessing sensitive files
}

// HourBucket holds an hour label and event count for timeline rendering.
type HourBucket struct {
	Hour  string // "YYYY-MM-DD HH:00"
	Count int
}

// Report is the complete analysis result.
type Report struct {
	// Sources is the list of file paths analyzed.
	Sources []string

	// Formats lists the detected formats.
	Formats []string

	// Period
	FirstEvent time.Time
	LastEvent  time.Time

	// Counts
	TotalEvents       int
	SuccessfulLogins  int
	FailedLogins      int
	PrivilegeEscs     int
	AccountsCreated   int
	GroupChanges      int
	Disconnects       int
	OtherEvents       int

	// Rankings
	TopFailedSources  []CountEntry
	TopTargetAccounts []CountEntry
	TopSuccessSources []CountEntry

	// Brute force patterns
	BruteForce []*BruteForceResult

	// Privilege escalation events
	PrivEscEvents []*PrivEscEvent

	// Timeline: events grouped by hour
	Timeline []HourBucket
	PeakHour string
	PeakCount int

	// Verdict
	Suspicious bool
	SuspectReasons []string

	// Raw filtered events (for verbose output)
	Events []*parser.AuthEvent
}

// Analyze runs the full analysis pipeline on the provided events.
func Analyze(events []*parser.AuthEvent, sources []string, formats []string, cfg Config) *Report {
	// Apply time filters
	filtered := filterEvents(events, cfg.Since, cfg.Until)

	r := &Report{
		Sources: sources,
		Formats: formats,
		Events:  filtered,
	}

	if len(filtered) == 0 {
		return r
	}

	// Sort events chronologically
	sort.Slice(filtered, func(i, j int) bool {
		return filtered[i].Timestamp.Before(filtered[j].Timestamp)
	})

	// Time bounds
	r.FirstEvent = filtered[0].Timestamp
	r.LastEvent = filtered[len(filtered)-1].Timestamp
	r.TotalEvents = len(filtered)

	// Count by type, build IP/account frequency maps
	failedByIP := make(map[string]int)
	failedByUser := make(map[string]int)
	successByIP := make(map[string]int)

	for _, ev := range filtered {
		switch ev.Type {
		case parser.EventLoginSuccess, parser.EventExplicitCred:
			r.SuccessfulLogins++
			if ev.SourceIP != "" {
				successByIP[ev.SourceIP]++
			}
		case parser.EventLoginFailure, parser.EventInvalidUser:
			r.FailedLogins++
			if ev.SourceIP != "" {
				failedByIP[ev.SourceIP]++
			}
			if ev.Username != "" {
				failedByUser[ev.Username]++
			}
		case parser.EventPrivilegeEsc:
			r.PrivilegeEscs++
		case parser.EventAccountCreated:
			r.AccountsCreated++
		case parser.EventGroupChange:
			r.GroupChanges++
		case parser.EventDisconnect:
			r.Disconnects++
		default:
			r.OtherEvents++
		}
	}

	// Rankings
	r.TopFailedSources = topN(failedByIP, cfg.TopN)
	r.TopTargetAccounts = topN(failedByUser, cfg.TopN)
	r.TopSuccessSources = topN(successByIP, cfg.TopN)

	// Brute force detection
	r.BruteForce = DetectBruteForce(filtered, cfg.BruteForce)

	// Privilege escalation events
	r.PrivEscEvents = extractPrivEsc(filtered)

	// Timeline
	r.Timeline, r.PeakHour, r.PeakCount = buildTimeline(filtered)

	// Verdict
	r.evaluateVerdict()

	return r
}

func filterEvents(events []*parser.AuthEvent, since, until time.Time) []*parser.AuthEvent {
	if since.IsZero() && until.IsZero() {
		return events
	}
	out := make([]*parser.AuthEvent, 0, len(events))
	for _, ev := range events {
		if !since.IsZero() && ev.Timestamp.Before(since) {
			continue
		}
		if !until.IsZero() && ev.Timestamp.After(until) {
			continue
		}
		out = append(out, ev)
	}
	return out
}

// topN converts a count map into a sorted slice of CountEntry, capped at n.
func topN(m map[string]int, n int) []CountEntry {
	entries := make([]CountEntry, 0, len(m))
	for k, v := range m {
		if k == "" {
			continue
		}
		entries = append(entries, CountEntry{Name: k, Count: v})
	}
	sort.Slice(entries, func(i, j int) bool {
		if entries[i].Count != entries[j].Count {
			return entries[i].Count > entries[j].Count
		}
		return entries[i].Name < entries[j].Name
	})
	if n > 0 && len(entries) > n {
		entries = entries[:n]
	}
	return entries
}

// Sensitive command fragments that warrant extra attention
var sensitiveCmds = []string{
	"/etc/shadow", "/etc/passwd", "/etc/sudoers",
	"netcat", "nc ", "wget", "curl",
	"chmod 777", "chmod +s", "chown root",
	"base64", "python -c", "perl -e", "ruby -e",
}

func extractPrivEsc(events []*parser.AuthEvent) []*PrivEscEvent {
	var out []*PrivEscEvent
	for _, ev := range events {
		if !ev.IsPrivilegeEsc() {
			continue
		}
		pe := &PrivEscEvent{
			Timestamp: ev.Timestamp,
			Username:  ev.Username,
			Command:   ev.SudoCommand,
			Message:   ev.Message,
		}
		// Check for sensitive commands
		for _, s := range sensitiveCmds {
			if containsCI(ev.SudoCommand, s) || containsCI(ev.Message, s) {
				pe.Sensitive = true
				break
			}
		}
		out = append(out, pe)
	}
	return out
}

func containsCI(s, sub string) bool {
	if s == "" || sub == "" {
		return false
	}
	sl := len(sub)
	for i := 0; i <= len(s)-sl; i++ {
		match := true
		for j := 0; j < sl; j++ {
			c1, c2 := s[i+j], sub[j]
			if c1 >= 'A' && c1 <= 'Z' {
				c1 += 32
			}
			if c2 >= 'A' && c2 <= 'Z' {
				c2 += 32
			}
			if c1 != c2 {
				match = false
				break
			}
		}
		if match {
			return true
		}
	}
	return false
}

func buildTimeline(events []*parser.AuthEvent) (buckets []HourBucket, peakHour string, peakCount int) {
	counts := make(map[string]int)
	for _, ev := range events {
		if ev.Timestamp.IsZero() {
			continue
		}
		key := ev.Timestamp.UTC().Format("2006-01-02 15:00")
		counts[key]++
	}

	keys := make([]string, 0, len(counts))
	for k := range counts {
		keys = append(keys, k)
	}
	sort.Strings(keys)

	for _, k := range keys {
		c := counts[k]
		buckets = append(buckets, HourBucket{Hour: k, Count: c})
		if c > peakCount {
			peakCount = c
			peakHour = k
		}
	}
	return
}

func (r *Report) evaluateVerdict() {
	for _, bf := range r.BruteForce {
		if bf.FollowedBySuccess {
			r.Suspicious = true
			r.SuspectReasons = append(r.SuspectReasons,
				"brute force with subsequent successful login detected")
		} else {
			r.Suspicious = true
			r.SuspectReasons = append(r.SuspectReasons,
				"brute force pattern detected from "+bf.SourceIP)
		}
	}
	for _, pe := range r.PrivEscEvents {
		if pe.Sensitive {
			r.Suspicious = true
			r.SuspectReasons = append(r.SuspectReasons,
				"sensitive privilege escalation command: "+pe.Command)
		}
	}
	if r.AccountsCreated > 0 {
		r.Suspicious = true
		r.SuspectReasons = append(r.SuspectReasons,
			"new user accounts were created during this period")
	}
	if r.GroupChanges > 0 {
		r.Suspicious = true
		r.SuspectReasons = append(r.SuspectReasons,
			"security group membership changes detected")
	}
}
