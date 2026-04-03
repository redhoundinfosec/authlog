package parser

import (
	"testing"
	"time"
)

func TestLinuxParser_AcceptedSSH(t *testing.T) {
	input := `Apr  3 14:22:01 server sshd[12345]: Accepted publickey for admin from 192.168.1.100 port 54321 ssh2`
	p := NewLinuxParser()
	p.Year = 2026
	events, err := p.Parse([]byte(input))
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if len(events) != 1 {
		t.Fatalf("expected 1 event, got %d", len(events))
	}
	ev := events[0]
	if ev.Type != EventLoginSuccess {
		t.Errorf("expected EventLoginSuccess, got %v", ev.Type)
	}
	if ev.Username != "admin" {
		t.Errorf("expected username=admin, got %v", ev.Username)
	}
	if ev.SourceIP != "192.168.1.100" {
		t.Errorf("expected SourceIP=192.168.1.100, got %v", ev.SourceIP)
	}
	if ev.AuthMethod != "publickey" {
		t.Errorf("expected AuthMethod=publickey, got %v", ev.AuthMethod)
	}
	if ev.Format != FormatLinux {
		t.Errorf("expected FormatLinux, got %v", ev.Format)
	}
	if ev.Hostname != "server" {
		t.Errorf("expected hostname=server, got %v", ev.Hostname)
	}
}

func TestLinuxParser_FailedPassword(t *testing.T) {
	input := `Apr  3 14:23:05 server sshd[12346]: Failed password for root from 10.0.0.50 port 22222 ssh2`
	p := NewLinuxParser()
	p.Year = 2026
	events, err := p.Parse([]byte(input))
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if len(events) != 1 {
		t.Fatalf("expected 1 event, got %d", len(events))
	}
	ev := events[0]
	if ev.Type != EventLoginFailure {
		t.Errorf("expected EventLoginFailure, got %v", ev.Type)
	}
	if ev.Username != "root" {
		t.Errorf("expected username=root, got %v", ev.Username)
	}
	if ev.SourceIP != "10.0.0.50" {
		t.Errorf("expected SourceIP=10.0.0.50, got %v", ev.SourceIP)
	}
}

func TestLinuxParser_InvalidUser(t *testing.T) {
	input := `Apr  3 14:24:10 server sshd[12347]: Invalid user deploy from 10.0.0.99 port 31337`
	p := NewLinuxParser()
	p.Year = 2026
	events, err := p.Parse([]byte(input))
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if len(events) != 1 {
		t.Fatalf("expected 1 event, got %d", len(events))
	}
	ev := events[0]
	if ev.Type != EventInvalidUser {
		t.Errorf("expected EventInvalidUser, got %v", ev.Type)
	}
	if ev.Username != "deploy" {
		t.Errorf("expected username=deploy, got %v", ev.Username)
	}
}

func TestLinuxParser_Sudo(t *testing.T) {
	input := `Apr  3 14:30:15 server sudo:  admin : TTY=pts/0 ; PWD=/home/admin ; USER=root ; COMMAND=/usr/bin/apt update`
	p := NewLinuxParser()
	p.Year = 2026
	events, err := p.Parse([]byte(input))
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if len(events) != 1 {
		t.Fatalf("expected 1 event, got %d: %v", len(events), err)
	}
	ev := events[0]
	if ev.Type != EventPrivilegeEsc {
		t.Errorf("expected EventPrivilegeEsc, got %v", ev.Type)
	}
	if ev.Username != "admin" {
		t.Errorf("expected username=admin, got %q", ev.Username)
	}
	if ev.SudoCommand == "" {
		t.Error("expected SudoCommand to be set")
	}
}

func TestLinuxParser_MultipleEvents(t *testing.T) {
	input := `Apr  3 14:22:01 server sshd[1]: Accepted publickey for alice from 192.168.1.5 port 11111 ssh2
Apr  3 14:22:02 server sshd[2]: Failed password for bob from 10.0.0.1 port 22222 ssh2
Apr  3 14:22:03 server sshd[3]: Invalid user nobody from 10.0.0.2 port 33333
Apr  3 14:22:04 server sudo:  alice : TTY=pts/1 ; PWD=/ ; USER=root ; COMMAND=/bin/bash`
	p := NewLinuxParser()
	p.Year = 2026
	events, err := p.Parse([]byte(input))
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if len(events) != 4 {
		t.Fatalf("expected 4 events, got %d", len(events))
	}
	types := []EventType{EventLoginSuccess, EventLoginFailure, EventInvalidUser, EventPrivilegeEsc}
	for i, expected := range types {
		if events[i].Type != expected {
			t.Errorf("event[%d]: expected %v, got %v", i, expected, events[i].Type)
		}
	}
}

func TestLinuxParser_Timestamp(t *testing.T) {
	input := `Apr  3 14:22:01 server sshd[1]: Accepted password for user1 from 1.2.3.4 port 50000 ssh2`
	p := NewLinuxParser()
	p.Year = 2026
	events, _ := p.Parse([]byte(input))
	if len(events) == 0 {
		t.Fatal("no events parsed")
	}
	ev := events[0]
	expected := time.Date(2026, time.April, 3, 14, 22, 1, 0, time.UTC)
	if !ev.Timestamp.Equal(expected) {
		t.Errorf("expected timestamp %v, got %v", expected, ev.Timestamp)
	}
}

func TestLinuxParser_EmptyInput(t *testing.T) {
	p := NewLinuxParser()
	events, err := p.Parse([]byte(""))
	if err != nil {
		t.Fatalf("unexpected error on empty input: %v", err)
	}
	if len(events) != 0 {
		t.Errorf("expected 0 events on empty input, got %d", len(events))
	}
}

func TestLinuxParser_Format(t *testing.T) {
	p := NewLinuxParser()
	if p.Format() != FormatLinux {
		t.Errorf("expected FormatLinux, got %v", p.Format())
	}
}
