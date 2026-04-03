package analyzer

import (
	"testing"
	"time"

	"github.com/redhoundinfosec/authlog/internal/parser"
)

func makeEvent(typ parser.EventType, ip, user string, t time.Time) *parser.AuthEvent {
	return &parser.AuthEvent{
		Type:      typ,
		SourceIP:  ip,
		Username:  user,
		Timestamp: t,
		Format:    parser.FormatLinux,
		Message:   string(typ) + " " + user,
	}
}

func TestAnalyze_BasicCounts(t *testing.T) {
	base := time.Date(2026, 4, 3, 14, 0, 0, 0, time.UTC)
	events := []*parser.AuthEvent{
		makeEvent(parser.EventLoginSuccess, "192.168.1.1", "alice", base),
		makeEvent(parser.EventLoginSuccess, "192.168.1.2", "bob", base.Add(1*time.Minute)),
		makeEvent(parser.EventLoginFailure, "10.0.0.50", "root", base.Add(2*time.Minute)),
		makeEvent(parser.EventLoginFailure, "10.0.0.50", "admin", base.Add(3*time.Minute)),
		makeEvent(parser.EventLoginFailure, "10.0.0.50", "admin", base.Add(4*time.Minute)),
		makeEvent(parser.EventPrivilegeEsc, "", "alice", base.Add(5*time.Minute)),
	}

	cfg := DefaultConfig()
	r := Analyze(events, []string{"test.log"}, []string{"linux"}, cfg)

	if r.SuccessfulLogins != 2 {
		t.Errorf("expected 2 successful logins, got %d", r.SuccessfulLogins)
	}
	if r.FailedLogins != 3 {
		t.Errorf("expected 3 failed logins, got %d", r.FailedLogins)
	}
	if r.PrivilegeEscs != 1 {
		t.Errorf("expected 1 privilege escalation, got %d", r.PrivilegeEscs)
	}
	if r.TotalEvents != 6 {
		t.Errorf("expected 6 total events, got %d", r.TotalEvents)
	}
}

func TestAnalyze_TopFailedSources(t *testing.T) {
	base := time.Date(2026, 4, 3, 14, 0, 0, 0, time.UTC)
	events := []*parser.AuthEvent{
		makeEvent(parser.EventLoginFailure, "10.0.0.1", "root", base),
		makeEvent(parser.EventLoginFailure, "10.0.0.1", "root", base.Add(1*time.Minute)),
		makeEvent(parser.EventLoginFailure, "10.0.0.1", "root", base.Add(2*time.Minute)),
		makeEvent(parser.EventLoginFailure, "10.0.0.2", "admin", base.Add(3*time.Minute)),
		makeEvent(parser.EventLoginFailure, "10.0.0.2", "admin", base.Add(4*time.Minute)),
	}

	cfg := DefaultConfig()
	r := Analyze(events, nil, nil, cfg)

	if len(r.TopFailedSources) == 0 {
		t.Fatal("expected TopFailedSources to be populated")
	}
	if r.TopFailedSources[0].Name != "10.0.0.1" {
		t.Errorf("expected top source 10.0.0.1, got %v", r.TopFailedSources[0].Name)
	}
	if r.TopFailedSources[0].Count != 3 {
		t.Errorf("expected count=3 for 10.0.0.1, got %d", r.TopFailedSources[0].Count)
	}
}

func TestAnalyze_TimeFilter(t *testing.T) {
	base := time.Date(2026, 4, 3, 14, 0, 0, 0, time.UTC)
	events := []*parser.AuthEvent{
		makeEvent(parser.EventLoginFailure, "10.0.0.1", "root", base),
		makeEvent(parser.EventLoginFailure, "10.0.0.1", "root", base.Add(1*time.Hour)),
		makeEvent(parser.EventLoginFailure, "10.0.0.1", "root", base.Add(2*time.Hour)),
	}

	cfg := DefaultConfig()
	cfg.Since = base.Add(30 * time.Minute)
	cfg.Until = base.Add(90 * time.Minute)
	r := Analyze(events, nil, nil, cfg)

	if r.TotalEvents != 1 {
		t.Errorf("expected 1 event after time filter, got %d", r.TotalEvents)
	}
}

func TestAnalyze_EmptyEvents(t *testing.T) {
	cfg := DefaultConfig()
	r := Analyze(nil, []string{"empty.log"}, nil, cfg)
	if r.TotalEvents != 0 {
		t.Errorf("expected 0 events, got %d", r.TotalEvents)
	}
	if r.Suspicious {
		t.Error("expected non-suspicious result for empty input")
	}
}

func TestAnalyze_SuspiciousBruteForce(t *testing.T) {
	base := time.Date(2026, 4, 3, 14, 0, 0, 0, time.UTC)
	var events []*parser.AuthEvent
	// 6 failures in 1 minute
	for i := 0; i < 6; i++ {
		events = append(events, makeEvent(parser.EventLoginFailure, "10.0.0.50", "root",
			base.Add(time.Duration(i)*10*time.Second)))
	}
	// Success after
	events = append(events, makeEvent(parser.EventLoginSuccess, "10.0.0.50", "root",
		base.Add(3*time.Minute)))

	cfg := DefaultConfig()
	r := Analyze(events, nil, nil, cfg)

	if !r.Suspicious {
		t.Error("expected Suspicious=true for brute force + success")
	}
}

func TestAnalyze_AccountCreationSuspicious(t *testing.T) {
	base := time.Date(2026, 4, 3, 14, 0, 0, 0, time.UTC)
	events := []*parser.AuthEvent{
		makeEvent(parser.EventAccountCreated, "", "backdoor", base),
	}

	cfg := DefaultConfig()
	r := Analyze(events, nil, nil, cfg)

	if !r.Suspicious {
		t.Error("expected Suspicious=true for account creation")
	}
}

func TestAnalyze_Timeline(t *testing.T) {
	base := time.Date(2026, 4, 3, 14, 0, 0, 0, time.UTC)
	events := []*parser.AuthEvent{
		makeEvent(parser.EventLoginFailure, "10.0.0.1", "root", base),
		makeEvent(parser.EventLoginFailure, "10.0.0.1", "root", base.Add(10*time.Minute)),
		makeEvent(parser.EventLoginSuccess, "192.168.1.1", "alice", base.Add(2*time.Hour)),
	}

	cfg := DefaultConfig()
	r := Analyze(events, nil, nil, cfg)

	if len(r.Timeline) == 0 {
		t.Error("expected Timeline to be populated")
	}
	if r.PeakHour == "" {
		t.Error("expected PeakHour to be set")
	}
}

func TestAnalyze_Sources(t *testing.T) {
	cfg := DefaultConfig()
	sources := []string{"auth.log", "secure"}
	formats := []string{"linux"}
	r := Analyze(nil, sources, formats, cfg)

	if len(r.Sources) != 2 {
		t.Errorf("expected 2 sources, got %d", len(r.Sources))
	}
}
