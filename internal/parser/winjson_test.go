package parser

import (
	"testing"
)

const sampleWinJSON = `[
  {
    "Id": 4625,
    "TimeCreated": "2026-04-03T14:22:01Z",
    "MachineName": "WIN-SERVER",
    "ProviderName": "Microsoft-Windows-Security-Auditing",
    "Properties": [
      {"Value": "0"},
      {"Value": "0"},
      {"Value": "S-1-0-0"},
      {"Value": "-"},
      {"Value": "-"},
      {"Value": "Administrator"},
      {"Value": "WIN-SERVER"},
      {"Value": "0x0"},
      {"Value": "3"},
      {"Value": "NtLmSsp"},
      {"Value": "10"},
      {"Value": "%%2313"},
      {"Value": "%%2304"},
      {"Value": "%%2307"},
      {"Value": "-"},
      {"Value": "-"},
      {"Value": "0xC000006D"},
      {"Value": "0xC000006A"},
      {"Value": "-"},
      {"Value": "10.0.0.50"},
      {"Value": "54321"}
    ],
    "Message": "An account failed to log on."
  },
  {
    "Id": 4624,
    "TimeCreated": "2026-04-03T14:30:00Z",
    "MachineName": "WIN-SERVER",
    "ProviderName": "Microsoft-Windows-Security-Auditing",
    "Properties": [
      {"Value": "0"},
      {"Value": "0"},
      {"Value": "S-1-5-18"},
      {"Value": "SYSTEM"},
      {"Value": "NT AUTHORITY"},
      {"Value": "alice"},
      {"Value": "WIN-SERVER"},
      {"Value": "0xdeadbeef"},
      {"Value": "3"},
      {"Value": "Kerberos"},
      {"Value": "Kerberos"},
      {"Value": "-"},
      {"Value": "0"},
      {"Value": "0"},
      {"Value": "0x0"},
      {"Value": "-"},
      {"Value": "-"},
      {"Value": "0"},
      {"Value": "-"},
      {"Value": "192.168.1.100"},
      {"Value": "49152"}
    ],
    "Message": "An account was successfully logged on."
  },
  {
    "Id": 4672,
    "TimeCreated": "2026-04-03T14:30:01Z",
    "MachineName": "WIN-SERVER",
    "ProviderName": "Microsoft-Windows-Security-Auditing",
    "Properties": [
      {"Value": "S-1-5-21-..."},
      {"Value": "alice"},
      {"Value": "WIN-SERVER"},
      {"Value": "0x1234"},
      {"Value": "SeDebugPrivilege\nSeBackupPrivilege"}
    ],
    "Message": "Special privileges assigned to new logon."
  }
]`

func TestWinJSONParser_Parse(t *testing.T) {
	p := NewWinJSONParser()
	events, err := p.Parse([]byte(sampleWinJSON))
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if len(events) != 3 {
		t.Fatalf("expected 3 events, got %d", len(events))
	}
}

func TestWinJSONParser_FailedLogon(t *testing.T) {
	p := NewWinJSONParser()
	events, _ := p.Parse([]byte(sampleWinJSON))
	ev := events[0]
	if ev.Type != EventLoginFailure {
		t.Errorf("expected EventLoginFailure, got %v", ev.Type)
	}
	if ev.WindowsEventID != 4625 {
		t.Errorf("expected EventID=4625, got %d", ev.WindowsEventID)
	}
	if ev.SourceIP != "10.0.0.50" {
		t.Errorf("expected SourceIP=10.0.0.50, got %q", ev.SourceIP)
	}
}

func TestWinJSONParser_SuccessLogon(t *testing.T) {
	p := NewWinJSONParser()
	events, _ := p.Parse([]byte(sampleWinJSON))
	ev := events[1]
	if ev.Type != EventLoginSuccess {
		t.Errorf("expected EventLoginSuccess, got %v", ev.Type)
	}
	if ev.Username != "alice" {
		t.Errorf("expected username=alice, got %q", ev.Username)
	}
}

func TestWinJSONParser_PrivEsc(t *testing.T) {
	p := NewWinJSONParser()
	events, _ := p.Parse([]byte(sampleWinJSON))
	ev := events[2]
	if ev.Type != EventPrivilegeEsc {
		t.Errorf("expected EventPrivilegeEsc, got %v", ev.Type)
	}
	if ev.Username != "alice" {
		t.Errorf("expected username=alice, got %q", ev.Username)
	}
}

func TestWinJSONParser_SingleObject(t *testing.T) {
	input := `{
    "Id": 4720,
    "TimeCreated": "2026-04-03T15:00:00Z",
    "MachineName": "WIN-SERVER",
    "ProviderName": "Microsoft-Windows-Security-Auditing",
    "Properties": [
      {"Value": "newuser"},
      {"Value": "adminuser"}
    ],
    "Message": "A user account was created."
  }`
	p := NewWinJSONParser()
	events, err := p.Parse([]byte(input))
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if len(events) != 1 {
		t.Fatalf("expected 1 event, got %d", len(events))
	}
	if events[0].Type != EventAccountCreated {
		t.Errorf("expected EventAccountCreated, got %v", events[0].Type)
	}
}

func TestWinJSONParser_Format(t *testing.T) {
	p := NewWinJSONParser()
	if p.Format() != FormatWinJSON {
		t.Errorf("expected FormatWinJSON, got %v", p.Format())
	}
}

func TestWinJSONParser_Empty(t *testing.T) {
	p := NewWinJSONParser()
	events, err := p.Parse([]byte("[]"))
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if len(events) != 0 {
		t.Errorf("expected 0 events, got %d", len(events))
	}
}

func TestWinJSONParser_InvalidJSON(t *testing.T) {
	p := NewWinJSONParser()
	_, err := p.Parse([]byte("not json at all"))
	if err == nil {
		t.Error("expected error for invalid JSON, got nil")
	}
}
