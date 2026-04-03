package parser

import (
	"testing"
)

func TestDetectFormat_Linux(t *testing.T) {
	inputs := []string{
		`Apr  3 14:22:01 server sshd[12345]: Accepted publickey for admin from 192.168.1.100 port 22 ssh2`,
		`Apr  3 14:23:05 server sshd[12346]: Failed password for root from 10.0.0.1 port 22 ssh2`,
		`Apr  3 14:24:00 server sudo:  alice : TTY=pts/0 ; PWD=/ ; USER=root ; COMMAND=/bin/bash`,
	}
	for _, input := range inputs {
		got := DetectFormat([]byte(input))
		if got != FormatLinux {
			t.Errorf("expected FormatLinux for input %q, got %v", input[:30], got)
		}
	}
}

func TestDetectFormat_WinXML(t *testing.T) {
	inputs := []string{
		`<?xml version="1.0"?><Event xmlns="http://schemas.microsoft.com/win/2004/08/events/event"><System><EventID>4625</EventID></System></Event>`,
		`<Events><Event xmlns="http://schemas.microsoft.com/win/2004/08/events/event"><System></System></Event></Events>`,
		`<Event xmlns="http://schemas.microsoft.com/win/2004/08/events/event"><System><EventID>4624</EventID></System></Event>`,
	}
	for _, input := range inputs {
		got := DetectFormat([]byte(input))
		if got != FormatWinXML {
			t.Errorf("expected FormatWinXML for input %q, got %v", input[:40], got)
		}
	}
}

func TestDetectFormat_WinJSON(t *testing.T) {
	input := `[{"Id": 4625, "MachineName": "WIN-SERVER", "TimeCreated": "2026-04-03T00:00:00Z", "ProviderName": "Microsoft-Windows-Security-Auditing"}]`
	got := DetectFormat([]byte(input))
	if got != FormatWinJSON {
		t.Errorf("expected FormatWinJSON, got %v", got)
	}
}

func TestDetectFormat_Unknown(t *testing.T) {
	inputs := []string{
		``,
		`some random text`,
		`{"key": "value"}`,
	}
	for _, input := range inputs {
		got := DetectFormat([]byte(input))
		if got != FormatUnknown {
			t.Errorf("expected FormatUnknown for input %q, got %v", input, got)
		}
	}
}

func TestNewParser_Linux(t *testing.T) {
	p := NewParser(FormatLinux)
	if p == nil {
		t.Fatal("expected non-nil parser for FormatLinux")
	}
	if p.Format() != FormatLinux {
		t.Errorf("expected FormatLinux, got %v", p.Format())
	}
}

func TestNewParser_WinXML(t *testing.T) {
	p := NewParser(FormatWinXML)
	if p == nil {
		t.Fatal("expected non-nil parser for FormatWinXML")
	}
}

func TestNewParser_WinJSON(t *testing.T) {
	p := NewParser(FormatWinJSON)
	if p == nil {
		t.Fatal("expected non-nil parser for FormatWinJSON")
	}
}

func TestNewParser_Unknown(t *testing.T) {
	p := NewParser(FormatUnknown)
	if p != nil {
		t.Error("expected nil parser for FormatUnknown")
	}
}

func TestAutoParse_Linux(t *testing.T) {
	input := `Apr  3 14:22:01 server sshd[1]: Accepted password for alice from 1.2.3.4 port 22 ssh2
Apr  3 14:23:00 server sshd[2]: Failed password for bob from 5.6.7.8 port 22 ssh2`
	events, format, err := AutoParse([]byte(input))
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if format != FormatLinux {
		t.Errorf("expected FormatLinux, got %v", format)
	}
	if len(events) != 2 {
		t.Errorf("expected 2 events, got %d", len(events))
	}
}
