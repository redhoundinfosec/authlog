package analyzer

import (
	"testing"
	"time"

	"github.com/redhoundinfosec/authlog/internal/parser"
)

func makeFailure(ip, user string, t time.Time) *parser.AuthEvent {
	return &parser.AuthEvent{
		Type:      parser.EventLoginFailure,
		SourceIP:  ip,
		Username:  user,
		Timestamp: t,
		Format:    parser.FormatLinux,
	}
}

func makeSuccess(ip, user string, t time.Time) *parser.AuthEvent {
	return &parser.AuthEvent{
		Type:      parser.EventLoginSuccess,
		SourceIP:  ip,
		Username:  user,
		Timestamp: t,
		Format:    parser.FormatLinux,
	}
}

func TestDetectBruteForce_Basic(t *testing.T) {
	base := time.Date(2026, 4, 3, 14, 20, 0, 0, time.UTC)
	events := []*parser.AuthEvent{
		makeFailure("10.0.0.50", "root", base),
		makeFailure("10.0.0.50", "root", base.Add(10*time.Second)),
		makeFailure("10.0.0.50", "admin", base.Add(20*time.Second)),
		makeFailure("10.0.0.50", "admin", base.Add(30*time.Second)),
		makeFailure("10.0.0.50", "user", base.Add(40*time.Second)),
		makeFailure("10.0.0.50", "user", base.Add(50*time.Second)),
	}

	cfg := BruteForceConfig{Threshold: 5, Window: 5 * time.Minute}
	results := DetectBruteForce(events, cfg)

	if len(results) == 0 {
		t.Fatal("expected brute force detection, got none")
	}
	r := results[0]
	if r.SourceIP != "10.0.0.50" {
		t.Errorf("expected SourceIP=10.0.0.50, got %v", r.SourceIP)
	}
	if r.FailureCount < 5 {
		t.Errorf("expected FailureCount >= 5, got %d", r.FailureCount)
	}
}

func TestDetectBruteForce_BelowThreshold(t *testing.T) {
	base := time.Date(2026, 4, 3, 14, 20, 0, 0, time.UTC)
	events := []*parser.AuthEvent{
		makeFailure("10.0.0.50", "root", base),
		makeFailure("10.0.0.50", "root", base.Add(10*time.Second)),
		makeFailure("10.0.0.50", "admin", base.Add(20*time.Second)),
	}

	cfg := BruteForceConfig{Threshold: 5, Window: 5 * time.Minute}
	results := DetectBruteForce(events, cfg)

	if len(results) != 0 {
		t.Errorf("expected no brute force below threshold, got %d results", len(results))
	}
}

func TestDetectBruteForce_OutsideWindow(t *testing.T) {
	base := time.Date(2026, 4, 3, 14, 20, 0, 0, time.UTC)
	events := []*parser.AuthEvent{
		makeFailure("10.0.0.50", "root", base),
		makeFailure("10.0.0.50", "root", base.Add(2*time.Minute)),
		makeFailure("10.0.0.50", "admin", base.Add(4*time.Minute)),
		makeFailure("10.0.0.50", "admin", base.Add(6*time.Minute)),
		makeFailure("10.0.0.50", "user", base.Add(10*time.Minute)),
	}

	cfg := BruteForceConfig{Threshold: 5, Window: 5 * time.Minute}
	results := DetectBruteForce(events, cfg)

	if len(results) != 0 {
		t.Errorf("events spread over 10m should not trigger 5m window, got %d results", len(results))
	}
}

func TestDetectBruteForce_FollowedBySuccess(t *testing.T) {
	base := time.Date(2026, 4, 3, 14, 20, 0, 0, time.UTC)
	events := []*parser.AuthEvent{
		makeFailure("10.0.0.50", "root", base),
		makeFailure("10.0.0.50", "root", base.Add(10*time.Second)),
		makeFailure("10.0.0.50", "admin", base.Add(20*time.Second)),
		makeFailure("10.0.0.50", "admin", base.Add(30*time.Second)),
		makeFailure("10.0.0.50", "admin", base.Add(40*time.Second)),
		// Success after brute force
		makeSuccess("10.0.0.50", "admin", base.Add(5*time.Minute)),
	}

	cfg := BruteForceConfig{Threshold: 5, Window: 5 * time.Minute}
	results := DetectBruteForce(events, cfg)

	if len(results) == 0 {
		t.Fatal("expected brute force detection")
	}
	if !results[0].FollowedBySuccess {
		t.Error("expected FollowedBySuccess=true")
	}
	if results[0].SuccessEvent == nil {
		t.Error("expected SuccessEvent to be set")
	}
	if results[0].SuccessEvent.Username != "admin" {
		t.Errorf("expected SuccessEvent.Username=admin, got %v", results[0].SuccessEvent.Username)
	}
}

func TestDetectBruteForce_MultipleIPs(t *testing.T) {
	base := time.Date(2026, 4, 3, 14, 20, 0, 0, time.UTC)
	events := []*parser.AuthEvent{
		// IP A — 5 failures
		makeFailure("10.0.0.50", "root", base),
		makeFailure("10.0.0.50", "root", base.Add(10*time.Second)),
		makeFailure("10.0.0.50", "root", base.Add(20*time.Second)),
		makeFailure("10.0.0.50", "root", base.Add(30*time.Second)),
		makeFailure("10.0.0.50", "root", base.Add(40*time.Second)),
		// IP B — 3 failures (below threshold)
		makeFailure("10.0.0.99", "root", base),
		makeFailure("10.0.0.99", "root", base.Add(10*time.Second)),
		makeFailure("10.0.0.99", "root", base.Add(20*time.Second)),
	}

	cfg := BruteForceConfig{Threshold: 5, Window: 5 * time.Minute}
	results := DetectBruteForce(events, cfg)

	if len(results) != 1 {
		t.Fatalf("expected 1 brute force result (only IP A), got %d", len(results))
	}
	if results[0].SourceIP != "10.0.0.50" {
		t.Errorf("expected SourceIP=10.0.0.50, got %v", results[0].SourceIP)
	}
}

func TestDetectBruteForce_NoIPEvents(t *testing.T) {
	base := time.Date(2026, 4, 3, 14, 20, 0, 0, time.UTC)
	events := []*parser.AuthEvent{
		{Type: parser.EventLoginFailure, Username: "root", Timestamp: base},
		{Type: parser.EventLoginFailure, Username: "root", Timestamp: base.Add(10 * time.Second)},
		{Type: parser.EventLoginFailure, Username: "root", Timestamp: base.Add(20 * time.Second)},
		{Type: parser.EventLoginFailure, Username: "root", Timestamp: base.Add(30 * time.Second)},
		{Type: parser.EventLoginFailure, Username: "root", Timestamp: base.Add(40 * time.Second)},
	}

	cfg := BruteForceConfig{Threshold: 5, Window: 5 * time.Minute}
	results := DetectBruteForce(events, cfg)

	// Events without IPs should not trigger brute force
	if len(results) != 0 {
		t.Errorf("expected no results for events without IPs, got %d", len(results))
	}
}
