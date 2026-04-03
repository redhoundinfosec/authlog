package analyzer

import (
	"sort"
	"time"

	"github.com/redhoundinfosec/authlog/internal/parser"
)

// BruteForceResult describes a detected brute force pattern.
type BruteForceResult struct {
	// SourceIP is the attacker's IP address.
	SourceIP string

	// FailureCount is the number of failures in the window.
	FailureCount int

	// Window is the duration from first to last failure.
	Window time.Duration

	// TargetUsernames is the list of unique usernames targeted.
	TargetUsernames []string

	// FirstSeen is the timestamp of the first failure.
	FirstSeen time.Time

	// LastSeen is the timestamp of the last failure.
	LastSeen time.Time

	// FollowedBySuccess is true if a successful login from this IP
	// was recorded after the failures.
	FollowedBySuccess bool

	// SuccessEvent is the first success event after the brute force, if any.
	SuccessEvent *parser.AuthEvent
}

// BruteForceConfig holds tuning parameters for brute force detection.
type BruteForceConfig struct {
	// Threshold is the minimum number of failures within Window to trigger detection.
	Threshold int

	// Window is the time window for counting failures.
	Window time.Duration
}

// DefaultBruteForceConfig returns the default configuration (5 failures in 5 minutes).
func DefaultBruteForceConfig() BruteForceConfig {
	return BruteForceConfig{
		Threshold: 5,
		Window:    5 * time.Minute,
	}
}

// DetectBruteForce analyses events and returns detected brute force patterns.
func DetectBruteForce(events []*parser.AuthEvent, cfg BruteForceConfig) []*BruteForceResult {
	// Group failures by source IP, sorted chronologically
	type failureEntry struct {
		ts       time.Time
		username string
	}
	byIP := make(map[string][]failureEntry)

	for _, ev := range events {
		if !ev.IsFailure() || ev.SourceIP == "" {
			continue
		}
		byIP[ev.SourceIP] = append(byIP[ev.SourceIP], failureEntry{
			ts:       ev.Timestamp,
			username: ev.Username,
		})
	}

	// Build success map for post-brute-force compromise check
	// successByIP[ip] = earliest success after any failure
	successMap := buildSuccessMap(events)

	var results []*BruteForceResult

	for ip, failures := range byIP {
		// Sort by timestamp
		sort.Slice(failures, func(i, j int) bool {
			return failures[i].ts.Before(failures[j].ts)
		})

		// Sliding window scan
		n := len(failures)
		for start := 0; start < n; start++ {
			windowStart := failures[start].ts
			windowEnd := windowStart.Add(cfg.Window)

			// Find all failures within the window starting at 'start'
			end := start
			for end < n && !failures[end].ts.After(windowEnd) {
				end++
			}
			count := end - start
			if count < cfg.Threshold {
				continue
			}

			// Collect targeted usernames
			seen := make(map[string]bool)
			var targets []string
			for i := start; i < end; i++ {
				u := failures[i].username
				if u != "" && !seen[u] {
					seen[u] = true
					targets = append(targets, u)
				}
			}

			result := &BruteForceResult{
				SourceIP:        ip,
				FailureCount:    count,
				Window:          failures[end-1].ts.Sub(failures[start].ts),
				TargetUsernames: targets,
				FirstSeen:       failures[start].ts,
				LastSeen:        failures[end-1].ts,
			}

			// Check for success after brute force
			if succs, ok := successMap[ip]; ok {
				for _, sev := range succs {
					if sev.Timestamp.After(result.FirstSeen) {
						result.FollowedBySuccess = true
						result.SuccessEvent = sev
						break
					}
				}
			}

			results = append(results, result)

			// Skip past the current window to avoid duplicate results for same burst
			start = end - 1
		}
	}

	// Sort by failure count descending
	sort.Slice(results, func(i, j int) bool {
		return results[i].FailureCount > results[j].FailureCount
	})

	return results
}

// buildSuccessMap returns a map of IP -> sorted success events.
func buildSuccessMap(events []*parser.AuthEvent) map[string][]*parser.AuthEvent {
	m := make(map[string][]*parser.AuthEvent)
	for _, ev := range events {
		if ev.IsSuccess() && ev.SourceIP != "" {
			m[ev.SourceIP] = append(m[ev.SourceIP], ev)
		}
	}
	for ip := range m {
		sort.Slice(m[ip], func(i, j int) bool {
			return m[ip][i].Timestamp.Before(m[ip][j].Timestamp)
		})
	}
	return m
}
