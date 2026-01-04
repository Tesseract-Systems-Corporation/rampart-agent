package watcher

import (
	"testing"

	"github.com/Tesseract-Systems-Corporation/rampart-agent/pkg/event"
)

func TestSSHWatcherInterface(t *testing.T) {
	var _ Watcher = (*SSHWatcher)(nil)
}

func TestSSHWatcherName(t *testing.T) {
	w := NewSSHWatcher(SSHConfig{
		LogPath:    "/var/log/auth.log",
		FortressID: "fort_test",
		ServerID:   "srv_test",
	})
	if w.Name() != "ssh" {
		t.Errorf("Name() = %v, want ssh", w.Name())
	}
}

func TestSSHWatcherConfig(t *testing.T) {
	tests := []struct {
		name        string
		config      SSHConfig
		wantLogPath string
	}{
		{
			name: "default log path",
			config: SSHConfig{
				FortressID: "fort_test",
				ServerID:   "srv_test",
			},
			wantLogPath: "/var/log/auth.log",
		},
		{
			name: "custom log path",
			config: SSHConfig{
				LogPath:    "/var/log/secure",
				FortressID: "fort_test",
				ServerID:   "srv_test",
			},
			wantLogPath: "/var/log/secure",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			w := NewSSHWatcher(tt.config)
			if w.logPath != tt.wantLogPath {
				t.Errorf("logPath = %v, want %v", w.logPath, tt.wantLogPath)
			}
		})
	}
}

func TestParseSSHLogLine(t *testing.T) {
	tests := []struct {
		name        string
		line        string
		wantSuccess bool
		wantUser    string
		wantIP      string
		wantMethod  string
		wantNil     bool
	}{
		{
			name:        "successful key auth",
			line:        "Dec 29 10:30:15 server sshd[12345]: Accepted publickey for jordan from 192.168.1.100 port 54321 ssh2: RSA SHA256:abc123",
			wantSuccess: true,
			wantUser:    "jordan",
			wantIP:      "192.168.1.100",
			wantMethod:  "key",
		},
		{
			name:        "successful password auth",
			line:        "Dec 29 10:30:15 server sshd[12345]: Accepted password for admin from 10.0.0.5 port 22 ssh2",
			wantSuccess: true,
			wantUser:    "admin",
			wantIP:      "10.0.0.5",
			wantMethod:  "password",
		},
		{
			name:        "failed password auth",
			line:        "Dec 29 10:30:15 server sshd[12345]: Failed password for invalid user hacker from 1.2.3.4 port 22 ssh2",
			wantSuccess: false,
			wantUser:    "hacker",
			wantIP:      "1.2.3.4",
			wantMethod:  "password",
		},
		{
			name:        "failed publickey auth",
			line:        "Dec 29 10:30:15 server sshd[12345]: Failed publickey for root from 5.6.7.8 port 22 ssh2",
			wantSuccess: false,
			wantUser:    "root",
			wantIP:      "5.6.7.8",
			wantMethod:  "key",
		},
		{
			name:        "connection closed",
			line:        "Dec 29 10:30:15 server sshd[12345]: Connection closed by 192.168.1.100 port 54321 [preauth]",
			wantNil:     true,
		},
		{
			name:        "unrelated log line",
			line:        "Dec 29 10:30:15 server systemd[1]: Started Session 42 of user jordan.",
			wantNil:     true,
		},
		{
			name:        "empty line",
			line:        "",
			wantNil:     true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result := parseSSHLogLine(tt.line, "fort_test", "srv_test")

			if tt.wantNil {
				if result != nil {
					t.Errorf("expected nil, got %+v", result)
				}
				return
			}

			if result == nil {
				t.Fatal("expected event, got nil")
			}

			if result.Type != event.AccessSSH {
				t.Errorf("Type = %v, want %v", result.Type, event.AccessSSH)
			}

			payload := result.Payload
			if payload["success"] != tt.wantSuccess {
				t.Errorf("success = %v, want %v", payload["success"], tt.wantSuccess)
			}
			if payload["user"] != tt.wantUser {
				t.Errorf("user = %v, want %v", payload["user"], tt.wantUser)
			}
			if payload["source_ip"] != tt.wantIP {
				t.Errorf("source_ip = %v, want %v", payload["source_ip"], tt.wantIP)
			}
			if payload["auth_method"] != tt.wantMethod {
				t.Errorf("auth_method = %v, want %v", payload["auth_method"], tt.wantMethod)
			}
		})
	}
}

func TestParseSSHLogLineWithActor(t *testing.T) {
	line := "Dec 29 10:30:15 server sshd[12345]: Accepted publickey for jordan from 192.168.1.100 port 54321 ssh2: RSA SHA256:abc123"
	result := parseSSHLogLine(line, "fort_test", "srv_test")

	if result == nil {
		t.Fatal("expected event, got nil")
	}

	if result.Actor == nil {
		t.Fatal("expected actor, got nil")
	}

	if result.Actor.Type != event.ActorTypeUser {
		t.Errorf("Actor.Type = %v, want %v", result.Actor.Type, event.ActorTypeUser)
	}

	if result.Actor.Name != "jordan" {
		t.Errorf("Actor.Name = %v, want jordan", result.Actor.Name)
	}

	if result.Actor.IP != "192.168.1.100" {
		t.Errorf("Actor.IP = %v, want 192.168.1.100", result.Actor.IP)
	}
}

func TestSSHWatcherIsDuplicate(t *testing.T) {
	w := NewSSHWatcher(SSHConfig{
		FortressID: "fort_test",
		ServerID:   "srv_test",
	})

	key := "jordan:192.168.1.100:key:true"

	// First call should not be duplicate
	if w.isDuplicate(key) {
		t.Error("first call should not be duplicate")
	}

	// Second call immediately should be duplicate
	if !w.isDuplicate(key) {
		t.Error("immediate second call should be duplicate")
	}

	// Different key should not be duplicate
	if w.isDuplicate("admin:10.0.0.5:password:true") {
		t.Error("different key should not be duplicate")
	}
}

func TestSSHWatcherCleanupOldEvents(t *testing.T) {
	w := NewSSHWatcher(SSHConfig{
		FortressID: "fort_test",
		ServerID:   "srv_test",
	})

	// Add an event
	key := "jordan:192.168.1.100:key:true"
	w.isDuplicate(key)

	// Verify it's tracked
	if _, exists := w.recentEvents[key]; !exists {
		t.Error("event should be tracked")
	}

	// Cleanup should not remove recent events
	w.cleanupOldEvents()

	if _, exists := w.recentEvents[key]; !exists {
		t.Error("recent event should not be removed by cleanup")
	}
}

func TestParseSSHLogLineFailedPasswordValidUser(t *testing.T) {
	// Test failed password for valid user (without "invalid user" prefix)
	line := "Dec 29 10:30:15 server sshd[12345]: Failed password for root from 1.2.3.4 port 22 ssh2"
	result := parseSSHLogLine(line, "fort_test", "srv_test")

	if result == nil {
		t.Fatal("expected event, got nil")
	}

	if result.Payload["success"] != false {
		t.Errorf("success = %v, want false", result.Payload["success"])
	}
	if result.Payload["user"] != "root" {
		t.Errorf("user = %v, want root", result.Payload["user"])
	}
	if result.Payload["source_ip"] != "1.2.3.4" {
		t.Errorf("source_ip = %v, want 1.2.3.4", result.Payload["source_ip"])
	}
	if result.Payload["auth_method"] != "password" {
		t.Errorf("auth_method = %v, want password", result.Payload["auth_method"])
	}
}

func TestParseSSHLogLineVariations(t *testing.T) {
	tests := []struct {
		name     string
		line     string
		wantUser string
		wantIP   string
	}{
		{
			name:     "IPv6 address",
			line:     "Dec 29 10:30:15 server sshd[12345]: Accepted publickey for admin from ::1 port 54321 ssh2",
			wantUser: "admin",
			wantIP:   "::1",
		},
		{
			name:     "different port",
			line:     "Dec 29 10:30:15 server sshd[12345]: Accepted password for user1 from 10.20.30.40 port 2222 ssh2",
			wantUser: "user1",
			wantIP:   "10.20.30.40",
		},
		{
			name:     "user with numbers",
			line:     "Dec 29 10:30:15 server sshd[12345]: Accepted publickey for user123 from 192.168.0.1 port 22 ssh2",
			wantUser: "user123",
			wantIP:   "192.168.0.1",
		},
		{
			name:     "user with underscore",
			line:     "Dec 29 10:30:15 server sshd[12345]: Accepted publickey for test_user from 172.16.0.1 port 22 ssh2",
			wantUser: "test_user",
			wantIP:   "172.16.0.1",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result := parseSSHLogLine(tt.line, "fort_test", "srv_test")

			if result == nil {
				t.Fatal("expected event, got nil")
			}

			if result.Payload["user"] != tt.wantUser {
				t.Errorf("user = %v, want %v", result.Payload["user"], tt.wantUser)
			}
			if result.Payload["source_ip"] != tt.wantIP {
				t.Errorf("source_ip = %v, want %v", result.Payload["source_ip"], tt.wantIP)
			}
		})
	}
}

func TestSSHWatcherFortressAndServerID(t *testing.T) {
	line := "Dec 29 10:30:15 server sshd[12345]: Accepted publickey for jordan from 192.168.1.100 port 54321 ssh2"
	result := parseSSHLogLine(line, "fortress_abc", "server_xyz")

	if result == nil {
		t.Fatal("expected event, got nil")
	}

	if result.FortressID != "fortress_abc" {
		t.Errorf("FortressID = %v, want fortress_abc", result.FortressID)
	}
	if result.ServerID != "server_xyz" {
		t.Errorf("ServerID = %v, want server_xyz", result.ServerID)
	}
}
