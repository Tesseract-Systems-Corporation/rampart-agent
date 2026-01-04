package watcher

import (
	"context"
	"strings"
	"testing"
	"time"

	"github.com/Tesseract-Systems-Corporation/rampart-agent/pkg/event"
)

func TestDockerWatcherInterface(t *testing.T) {
	// Verify DockerWatcher implements Watcher
	var _ Watcher = (*DockerWatcher)(nil)
}

func TestDockerWatcherName(t *testing.T) {
	w := NewDockerWatcher(DockerConfig{
		SocketPath: "/var/run/docker.sock",
		FortressID: "fort_test",
		ServerID:   "srv_test",
	})
	if w.Name() != "docker" {
		t.Errorf("Name() = %v, want docker", w.Name())
	}
}

func TestDockerWatcherConfig(t *testing.T) {
	tests := []struct {
		name       string
		config     DockerConfig
		wantSocket string
	}{
		{
			name: "default socket",
			config: DockerConfig{
				FortressID: "fort_test",
				ServerID:   "srv_test",
			},
			wantSocket: "/var/run/docker.sock",
		},
		{
			name: "custom socket",
			config: DockerConfig{
				SocketPath: "/custom/docker.sock",
				FortressID: "fort_test",
				ServerID:   "srv_test",
			},
			wantSocket: "/custom/docker.sock",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			w := NewDockerWatcher(tt.config)
			if w.socketPath != tt.wantSocket {
				t.Errorf("socketPath = %v, want %v", w.socketPath, tt.wantSocket)
			}
		})
	}
}

func TestParseContainerEvent(t *testing.T) {
	tests := []struct {
		name      string
		action    string
		container string
		image     string
		wantType  event.EventType
	}{
		{
			name:      "container start",
			action:    "start",
			container: "nginx-web",
			image:     "nginx:latest",
			wantType:  event.ContainerStarted,
		},
		{
			name:      "container stop",
			action:    "stop",
			container: "nginx-web",
			image:     "nginx:latest",
			wantType:  event.ContainerStopped,
		},
		{
			name:      "container die",
			action:    "die",
			container: "nginx-web",
			image:     "nginx:latest",
			wantType:  event.ContainerStopped,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			e := parseContainerEvent(tt.action, tt.container, "abc123", tt.image, "fort_test", "srv_test", nil, nil, nil)
			if e == nil && (tt.wantType == event.ContainerStarted || tt.wantType == event.ContainerStopped) {
				t.Fatal("expected event but got nil")
			}
			if e != nil && e.Type != tt.wantType {
				t.Errorf("Type = %v, want %v", e.Type, tt.wantType)
			}
		})
	}
}

func TestParseContainerEventIgnoresIrrelevant(t *testing.T) {
	// These actions should not generate events
	// Note: exec_start IS tracked now (generates ContainerExec events for security monitoring)
	ignored := []string{"create", "attach", "detach", "exec_create", "exec_die"}

	for _, action := range ignored {
		t.Run(action, func(t *testing.T) {
			e := parseContainerEvent(action, "container", "id", "image", "fort", "srv", nil, nil, nil)
			if e != nil {
				t.Errorf("expected nil for action %q, got %v", action, e)
			}
		})
	}
}

func TestParseContainerEventWithSecurityPosture(t *testing.T) {
	posture := &SecurityPosture{
		Privileged:       true,
		RunAsRoot:        true,
		User:             "",
		ReadOnlyRootfs:   false,
		CapabilitiesAdd:  []string{"NET_ADMIN", "SYS_TIME"},
		CapabilitiesDrop: []string{"MKNOD"},
		SecurityOpts:     []string{"no-new-privileges"},
		HostNetwork:      true,
		HostPID:          false,
		HostIPC:          false,
	}

	e := parseContainerEvent("start", "test-container", "abc123", "alpine:latest", "fort_test", "srv_test", nil, nil, posture)
	if e == nil {
		t.Fatal("expected event but got nil")
	}

	if e.Type != event.ContainerStarted {
		t.Errorf("Type = %v, want %v", e.Type, event.ContainerStarted)
	}

	// Check that security_posture is in the payload
	sp, ok := e.Payload["security_posture"].(map[string]any)
	if !ok {
		t.Fatal("expected security_posture in payload")
	}

	if sp["privileged"] != true {
		t.Errorf("privileged = %v, want true", sp["privileged"])
	}
	if sp["run_as_root"] != true {
		t.Errorf("run_as_root = %v, want true", sp["run_as_root"])
	}
	if sp["host_network"] != true {
		t.Errorf("host_network = %v, want true", sp["host_network"])
	}
	if sp["host_pid"] != false {
		t.Errorf("host_pid = %v, want false", sp["host_pid"])
	}
	if sp["read_only_rootfs"] != false {
		t.Errorf("read_only_rootfs = %v, want false", sp["read_only_rootfs"])
	}

	caps, ok := sp["capabilities_add"].([]string)
	if !ok || len(caps) != 2 {
		t.Errorf("capabilities_add = %v, want [NET_ADMIN, SYS_TIME]", sp["capabilities_add"])
	}
}

func TestSecurityPostureRunAsRootDetection(t *testing.T) {
	tests := []struct {
		name       string
		user       string
		wantAsRoot bool
	}{
		{"empty user", "", true},
		{"uid 0", "0", true},
		{"root user", "root", true},
		{"uid 0 with group", "0:0", true},
		{"root with group", "root:root", true},
		{"non-root uid", "1000", false},
		{"non-root user", "nobody", false},
		{"non-root user with group", "nobody:nogroup", false},
		{"uid 1000 with group", "1000:1000", false},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			// Apply the same logic as getSecurityPosture
			user := tt.user
			runAsRoot := user == "" || user == "0" || user == "root" ||
				strings.HasPrefix(user, "0:") || strings.HasPrefix(user, "root:")

			if runAsRoot != tt.wantAsRoot {
				t.Errorf("RunAsRoot for user %q = %v, want %v", tt.user, runAsRoot, tt.wantAsRoot)
			}
		})
	}
}

func TestDockerWatcherContextCancellation(t *testing.T) {
	w := NewDockerWatcher(DockerConfig{
		SocketPath: "/nonexistent/docker.sock",
		FortressID: "fort_test",
		ServerID:   "srv_test",
	})

	ctx, cancel := context.WithCancel(context.Background())
	cancel() // Cancel immediately

	ch, err := w.Watch(ctx)
	// Should either error or return a closed channel
	if err == nil && ch != nil {
		select {
		case _, ok := <-ch:
			if ok {
				// If we got an event, the channel should eventually close
				for range ch {
				}
			}
		case <-time.After(100 * time.Millisecond):
			// Timeout is acceptable
		}
	}
}

func TestIsAutomatedExec(t *testing.T) {
	tests := []struct {
		name     string
		command  string
		expected bool
	}{
		{"empty command", "", false},
		{"bash shell", "/bin/bash", false},
		{"sh shell", "/bin/sh", false},
		{"interactive bash", "bash", false},
		{"wget healthcheck", "wget -q --spider http://localhost/health", true},
		{"wget spider", "wget --spider http://localhost", true},
		{"curl fail", "curl -f http://localhost/health", true},
		{"curl silent", "curl -s http://localhost:8080/ready", true},
		{"health endpoint", "/health", true},
		{"healthz endpoint", "/healthz", true},
		{"ready endpoint", "/ready", true},
		{"readyz endpoint", "/readyz", true},
		{"live endpoint", "/live", true},
		{"livez endpoint", "/livez", true},
		{"pg_isready", "pg_isready -h localhost", true},
		{"redis ping", "redis-cli ping", true},
		{"mysql ping", "mysqladmin ping -h localhost", true},
		{"mongo eval", "mongo --eval 'db.runCommand({ping:1})'", true},
		{"exit pattern", "test -f /ready || exit 1", true},
		{"and exit pattern", "test -f /ready && exit 0", true},
		{"normal command", "ls -la", false},
		{"cat command", "cat /etc/passwd", false},
		{"ps aux", "ps aux", false},
		{"custom script", "/app/my-script.sh", false},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result := isAutomatedExec(tt.command)
			if result != tt.expected {
				t.Errorf("isAutomatedExec(%q) = %v, want %v", tt.command, result, tt.expected)
			}
		})
	}
}

func TestDockerWatcherIsDuplicateEvent(t *testing.T) {
	w := NewDockerWatcher(DockerConfig{
		FortressID: "fort_test",
		ServerID:   "srv_test",
	})

	key := "container123:start"

	// First call should not be duplicate
	if w.isDuplicateEvent(key) {
		t.Error("first call should not be duplicate")
	}

	// Second call immediately should be duplicate
	if !w.isDuplicateEvent(key) {
		t.Error("immediate second call should be duplicate")
	}

	// Different key should not be duplicate
	if w.isDuplicateEvent("container456:start") {
		t.Error("different key should not be duplicate")
	}
}

func TestDockerWatcherCleanupOldEvents(t *testing.T) {
	w := NewDockerWatcher(DockerConfig{
		FortressID: "fort_test",
		ServerID:   "srv_test",
	})

	// Add an event
	key := "container123:start"
	w.isDuplicateEvent(key)

	// Verify it's tracked
	w.recentEventsMu.Lock()
	if _, exists := w.recentEvents[key]; !exists {
		t.Error("event should be tracked")
	}
	w.recentEventsMu.Unlock()

	// Cleanup should not remove recent events
	w.cleanupOldEvents()

	w.recentEventsMu.Lock()
	if _, exists := w.recentEvents[key]; !exists {
		t.Error("recent event should not be removed by cleanup")
	}
	w.recentEventsMu.Unlock()
}

func TestDockerWatcherContainerTracking(t *testing.T) {
	w := NewDockerWatcher(DockerConfig{
		FortressID: "fort_test",
		ServerID:   "srv_test",
	})

	// Initially empty
	w.containersMu.RLock()
	if len(w.containers) != 0 {
		t.Errorf("initial containers count = %d, want 0", len(w.containers))
	}
	w.containersMu.RUnlock()

	// Untrack non-existent container should not panic
	w.untrackContainer("nonexistent")
}

func TestParseContainerEventExecStart(t *testing.T) {
	tests := []struct {
		name       string
		action     string
		wantNil    bool
		wantType   event.EventType
		wantCmd    string
	}{
		{
			name:     "exec_start with command",
			action:   "exec_start: /bin/bash",
			wantNil:  false,
			wantType: event.ContainerExec,
			wantCmd:  "/bin/bash",
		},
		{
			name:    "exec_start with healthcheck",
			action:  "exec_start: curl -f http://localhost/health",
			wantNil: true,
		},
		{
			name:     "exec_start: ps aux",
			action:   "exec_start: ps aux",
			wantNil:  false,
			wantType: event.ContainerExec,
			wantCmd:  "ps aux",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			e := parseContainerEvent(tt.action, "test-container", "abc123", "alpine:latest", "fort_test", "srv_test", map[string]string{"execID": "exec123"}, nil, nil)

			if tt.wantNil {
				if e != nil {
					t.Errorf("expected nil, got %+v", e)
				}
				return
			}

			if e == nil {
				t.Fatal("expected event, got nil")
			}

			if e.Type != tt.wantType {
				t.Errorf("Type = %v, want %v", e.Type, tt.wantType)
			}

			if cmd, ok := e.Payload["command"].(string); ok {
				if cmd != tt.wantCmd {
					t.Errorf("command = %q, want %q", cmd, tt.wantCmd)
				}
			}
		})
	}
}

func TestParseContainerEventWithDeploymentInfo(t *testing.T) {
	deployInfo := &DeploymentInfo{
		GitCommit:   "abc123def456",
		GitRepo:     "https://github.com/example/app",
		GitBranch:   "main",
		Deployer:    "john@example.com",
		Version:     "1.2.3",
		Environment: "production",
	}

	e := parseContainerEvent("start", "my-app", "container123", "myapp:latest", "fort_test", "srv_test", nil, deployInfo, nil)

	if e == nil {
		t.Fatal("expected event, got nil")
	}

	if e.Payload["git_commit"] != "abc123def456" {
		t.Errorf("git_commit = %v, want abc123def456", e.Payload["git_commit"])
	}
	if e.Payload["git_repo"] != "https://github.com/example/app" {
		t.Errorf("git_repo = %v, want https://github.com/example/app", e.Payload["git_repo"])
	}
	if e.Payload["git_branch"] != "main" {
		t.Errorf("git_branch = %v, want main", e.Payload["git_branch"])
	}
	if e.Payload["deployer"] != "john@example.com" {
		t.Errorf("deployer = %v, want john@example.com", e.Payload["deployer"])
	}
	if e.Payload["version"] != "1.2.3" {
		t.Errorf("version = %v, want 1.2.3", e.Payload["version"])
	}
	if e.Payload["environment"] != "production" {
		t.Errorf("environment = %v, want production", e.Payload["environment"])
	}
}

func TestDockerWatcherConnectionScanInterval(t *testing.T) {
	tests := []struct {
		name         string
		config       DockerConfig
		wantInterval time.Duration
	}{
		{
			name: "default interval",
			config: DockerConfig{
				FortressID: "fort_test",
				ServerID:   "srv_test",
			},
			wantInterval: 30 * time.Second,
		},
		{
			name: "custom interval",
			config: DockerConfig{
				FortressID:             "fort_test",
				ServerID:               "srv_test",
				ConnectionScanInterval: 60 * time.Second,
			},
			wantInterval: 60 * time.Second,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			w := NewDockerWatcher(tt.config)
			if w.connectionScanInterval != tt.wantInterval {
				t.Errorf("connectionScanInterval = %v, want %v", w.connectionScanInterval, tt.wantInterval)
			}
		})
	}
}

func TestContainerConnectionParsing(t *testing.T) {
	w := NewDockerWatcher(DockerConfig{
		FortressID: "fort_test",
		ServerID:   "srv_test",
	})

	container := ContainerInfo{
		ID:   "container123",
		Name: "test-container",
		PID:  12345,
	}

	tests := []struct {
		name       string
		line       string
		wantNil    bool
		wantLocal  string
		wantRemote string
	}{
		{
			name:       "valid tcp line",
			line:       "   0: 0100007F:0050 0100007F:0051 01 00000000:00000000 00:00000000 00000000     0        0 12345 1 0000000000000000 100 0 0 10 0",
			wantNil:    false,
			wantLocal:  "127.0.0.1",
			wantRemote: "127.0.0.1",
		},
		{
			name:    "too few fields",
			line:    "   0: 0100007F:0050",
			wantNil: true,
		},
		{
			name:    "empty line",
			line:    "",
			wantNil: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			conn := w.parseTCPLine(tt.line, container)

			if tt.wantNil {
				if conn != nil {
					t.Errorf("expected nil, got %+v", conn)
				}
				return
			}

			if conn == nil {
				t.Fatal("expected connection, got nil")
			}

			if conn.LocalAddr != tt.wantLocal {
				t.Errorf("LocalAddr = %q, want %q", conn.LocalAddr, tt.wantLocal)
			}
			if conn.RemoteAddr != tt.wantRemote {
				t.Errorf("RemoteAddr = %q, want %q", conn.RemoteAddr, tt.wantRemote)
			}
		})
	}
}

func TestCreateContainerConnectionEvent(t *testing.T) {
	w := NewDockerWatcher(DockerConfig{
		FortressID: "fort_test",
		ServerID:   "srv_test",
	})

	conn := ContainerConnection{
		ContainerID:   "container123",
		ContainerName: "test-container",
		LocalAddr:     "172.17.0.2",
		LocalPort:     45678,
		RemoteAddr:    "93.184.216.34",
		RemotePort:    443,
		State:         "01",
	}

	e := w.createContainerConnectionEvent(conn)

	if e.Type != event.ConnectionEstablished {
		t.Errorf("Type = %v, want %v", e.Type, event.ConnectionEstablished)
	}
	if e.FortressID != "fort_test" {
		t.Errorf("FortressID = %v, want fort_test", e.FortressID)
	}
	if e.ServerID != "srv_test" {
		t.Errorf("ServerID = %v, want srv_test", e.ServerID)
	}
	if e.Payload["container_id"] != "container123" {
		t.Errorf("container_id = %v, want container123", e.Payload["container_id"])
	}
	if e.Payload["direction"] != "outbound" {
		t.Errorf("direction = %v, want outbound", e.Payload["direction"])
	}

	connPayload, ok := e.Payload["connection"].(map[string]any)
	if !ok {
		t.Fatal("expected connection in payload")
	}
	if connPayload["remote_port"] != 443 {
		t.Errorf("remote_port = %v, want 443", connPayload["remote_port"])
	}
	if connPayload["protocol"] != "tcp" {
		t.Errorf("protocol = %v, want tcp", connPayload["protocol"])
	}
}
