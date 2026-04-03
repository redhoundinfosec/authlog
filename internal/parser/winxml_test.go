package parser

import (
	"testing"
	"time"
)

const sampleWinXML = `<?xml version="1.0" encoding="UTF-8"?>
<Events>
<Event xmlns="http://schemas.microsoft.com/win/2004/08/events/event">
  <System>
    <Provider Name="Microsoft-Windows-Security-Auditing" Guid="{54849625-5478-4994-A5BA-3E3B0328C30D}"/>
    <EventID>4625</EventID>
    <TimeCreated SystemTime="2026-04-03T14:22:01.000000000Z"/>
    <Computer>WIN-SERVER</Computer>
  </System>
  <EventData>
    <Data Name="TargetUserName">Administrator</Data>
    <Data Name="IpAddress">10.0.0.50</Data>
    <Data Name="IpPort">54321</Data>
    <Data Name="LogonType">3</Data>
    <Data Name="SubStatus">0xC000006A</Data>
  </EventData>
</Event>
<Event xmlns="http://schemas.microsoft.com/win/2004/08/events/event">
  <System>
    <Provider Name="Microsoft-Windows-Security-Auditing"/>
    <EventID>4624</EventID>
    <TimeCreated SystemTime="2026-04-03T14:30:00.000000000Z"/>
    <Computer>WIN-SERVER</Computer>
  </System>
  <EventData>
    <Data Name="TargetUserName">alice</Data>
    <Data Name="IpAddress">192.168.1.100</Data>
    <Data Name="IpPort">49152</Data>
    <Data Name="LogonType">3</Data>
    <Data Name="AuthenticationPackageName">NTLM</Data>
  </EventData>
</Event>
<Event xmlns="http://schemas.microsoft.com/win/2004/08/events/event">
  <System>
    <Provider Name="Microsoft-Windows-Security-Auditing"/>
    <EventID>4672</EventID>
    <TimeCreated SystemTime="2026-04-03T14:30:01.000000000Z"/>
    <Computer>WIN-SERVER</Computer>
  </System>
  <EventData>
    <Data Name="SubjectUserName">alice</Data>
    <Data Name="PrivilegeList">SeDebugPrivilege
SeBackupPrivilege</Data>
  </EventData>
</Event>
<Event xmlns="http://schemas.microsoft.com/win/2004/08/events/event">
  <System>
    <Provider Name="Microsoft-Windows-Security-Auditing"/>
    <EventID>4720</EventID>
    <TimeCreated SystemTime="2026-04-03T15:00:00.000000000Z"/>
    <Computer>WIN-SERVER</Computer>
  </System>
  <EventData>
    <Data Name="TargetUserName">backdoor</Data>
    <Data Name="SubjectUserName">alice</Data>
  </EventData>
</Event>
</Events>`

func TestWinXMLParser_Parse(t *testing.T) {
	p := NewWinXMLParser()
	events, err := p.Parse([]byte(sampleWinXML))
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if len(events) != 4 {
		t.Fatalf("expected 4 events, got %d", len(events))
	}
}

func TestWinXMLParser_FailedLogon(t *testing.T) {
	p := NewWinXMLParser()
	events, _ := p.Parse([]byte(sampleWinXML))
	ev := events[0]
	if ev.Type != EventLoginFailure {
		t.Errorf("expected EventLoginFailure, got %v", ev.Type)
	}
	if ev.Username != "Administrator" {
		t.Errorf("expected username=Administrator, got %v", ev.Username)
	}
	if ev.SourceIP != "10.0.0.50" {
		t.Errorf("expected SourceIP=10.0.0.50, got %v", ev.SourceIP)
	}
	if ev.WindowsEventID != 4625 {
		t.Errorf("expected EventID=4625, got %v", ev.WindowsEventID)
	}
	if ev.WindowsLogonType != 3 {
		t.Errorf("expected LogonType=3, got %v", ev.WindowsLogonType)
	}
}

func TestWinXMLParser_SuccessLogon(t *testing.T) {
	p := NewWinXMLParser()
	events, _ := p.Parse([]byte(sampleWinXML))
	ev := events[1]
	if ev.Type != EventLoginSuccess {
		t.Errorf("expected EventLoginSuccess, got %v", ev.Type)
	}
	if ev.Username != "alice" {
		t.Errorf("expected username=alice, got %v", ev.Username)
	}
}

func TestWinXMLParser_PrivilegeEsc(t *testing.T) {
	p := NewWinXMLParser()
	events, _ := p.Parse([]byte(sampleWinXML))
	ev := events[2]
	if ev.Type != EventPrivilegeEsc {
		t.Errorf("expected EventPrivilegeEsc, got %v", ev.Type)
	}
	if ev.Username != "alice" {
		t.Errorf("expected username=alice, got %v", ev.Username)
	}
	if ev.WindowsEventID != 4672 {
		t.Errorf("expected EventID=4672, got %v", ev.WindowsEventID)
	}
}

func TestWinXMLParser_AccountCreated(t *testing.T) {
	p := NewWinXMLParser()
	events, _ := p.Parse([]byte(sampleWinXML))
	ev := events[3]
	if ev.Type != EventAccountCreated {
		t.Errorf("expected EventAccountCreated, got %v", ev.Type)
	}
	if ev.Username != "backdoor" {
		t.Errorf("expected username=backdoor, got %v", ev.Username)
	}
}

func TestWinXMLParser_Timestamp(t *testing.T) {
	p := NewWinXMLParser()
	events, _ := p.Parse([]byte(sampleWinXML))
	ev := events[0]
	expected := time.Date(2026, time.April, 3, 14, 22, 1, 0, time.UTC)
	if !ev.Timestamp.Equal(expected) {
		t.Errorf("expected timestamp %v, got %v", expected, ev.Timestamp)
	}
}

func TestWinXMLParser_Format(t *testing.T) {
	p := NewWinXMLParser()
	if p.Format() != FormatWinXML {
		t.Errorf("expected FormatWinXML, got %v", p.Format())
	}
}

func TestWinXMLParser_Empty(t *testing.T) {
	p := NewWinXMLParser()
	events, err := p.Parse([]byte("<Events></Events>"))
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if len(events) != 0 {
		t.Errorf("expected 0 events, got %d", len(events))
	}
}

func TestWrapXML_NoRoot(t *testing.T) {
	input := `<Event xmlns="http://schemas.microsoft.com/win/2004/08/events/event">
  <System><EventID>4624</EventID><TimeCreated SystemTime="2026-04-03T00:00:00Z"/><Computer>PC</Computer></System>
  <EventData><Data Name="TargetUserName">bob</Data><Data Name="LogonType">3</Data></EventData>
</Event>`
	p := NewWinXMLParser()
	events, err := p.Parse([]byte(input))
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if len(events) != 1 {
		t.Fatalf("expected 1 event, got %d", len(events))
	}
}
