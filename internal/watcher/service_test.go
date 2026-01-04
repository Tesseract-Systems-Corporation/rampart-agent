package watcher

import (
	"context"
	"runtime"
	"testing"
	"time"

	"github.com/Tesseract-Systems-Corporation/rampart-agent/pkg/event"
)

func TestServiceWatcherInterface(t *testing.T) {
	// Verify ServiceWatcher implements Watcher
	var _ Watcher = (*ServiceWatcher)(nil)
}

func TestServiceWatcherName(t *testing.T) {
	w := NewServiceWatcher(ServiceConfig{
		FortressID: "fort_test",
		ServerID:   "srv_test",
	})
	if w.Name() != "service" {
		t.Errorf("Name() = %v, want service", w.Name())
	}
}

func TestServiceWatcherConfig(t *testing.T) {
	tests := []struct {
		name         string
		config       ServiceConfig
		wantInterval time.Duration
	}{
		{
			name: "default interval",
			config: ServiceConfig{
				FortressID: "fort_test",
				ServerID:   "srv_test",
			},
			wantInterval: DefaultServicePollInterval,
		},
		{
			name: "custom interval",
			config: ServiceConfig{
				PollInterval: 30 * time.Second,
				FortressID:   "fort_test",
				ServerID:     "srv_test",
			},
			wantInterval: 30 * time.Second,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			w := NewServiceWatcher(tt.config)
			if w.pollInterval != tt.wantInterval {
				t.Errorf("pollInterval = %v, want %v", w.pollInterval, tt.wantInterval)
			}
		})
	}
}

func TestParseSystemctlOutput(t *testing.T) {
	tests := []struct {
		name     string
		output   string
		expected map[string]ServiceState
	}{
		{
			name: "typical services",
			output: `  nginx.service                          loaded active   running  A high performance web server
  ssh.service                            loaded active   running  OpenBSD Secure Shell server
  docker.service                         loaded active   running  Docker Application Container Engine
  cron.service                           loaded active   running  Regular background program processing daemon`,
			expected: map[string]ServiceState{
				"nginx": {
					Name:        "nginx",
					LoadState:   "loaded",
					ActiveState: "active",
					SubState:    "running",
				},
				"ssh": {
					Name:        "ssh",
					LoadState:   "loaded",
					ActiveState: "active",
					SubState:    "running",
				},
				"docker": {
					Name:        "docker",
					LoadState:   "loaded",
					ActiveState: "active",
					SubState:    "running",
				},
				"cron": {
					Name:        "cron",
					LoadState:   "loaded",
					ActiveState: "active",
					SubState:    "running",
				},
			},
		},
		{
			name: "inactive and failed services",
			output: `  nginx.service                          loaded inactive dead     A high performance web server
  mysql.service                          loaded failed   failed   MySQL Community Server
  apache2.service                        not-found inactive dead   apache2.service`,
			expected: map[string]ServiceState{
				"nginx": {
					Name:        "nginx",
					LoadState:   "loaded",
					ActiveState: "inactive",
					SubState:    "dead",
				},
				"mysql": {
					Name:        "mysql",
					LoadState:   "loaded",
					ActiveState: "failed",
					SubState:    "failed",
				},
				"apache2": {
					Name:        "apache2",
					LoadState:   "not-found",
					ActiveState: "inactive",
					SubState:    "dead",
				},
			},
		},
		{
			name:     "empty output",
			output:   "",
			expected: map[string]ServiceState{},
		},
		{
			name:     "whitespace only",
			output:   "   \n   \n   ",
			expected: map[string]ServiceState{},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result := parseSystemctlOutput(tt.output)

			if len(result) != len(tt.expected) {
				t.Errorf("got %d services, want %d", len(result), len(tt.expected))
			}

			for name, expected := range tt.expected {
				got, exists := result[name]
				if !exists {
					t.Errorf("missing service %s", name)
					continue
				}
				if got.Name != expected.Name {
					t.Errorf("service %s: Name = %v, want %v", name, got.Name, expected.Name)
				}
				if got.LoadState != expected.LoadState {
					t.Errorf("service %s: LoadState = %v, want %v", name, got.LoadState, expected.LoadState)
				}
				if got.ActiveState != expected.ActiveState {
					t.Errorf("service %s: ActiveState = %v, want %v", name, got.ActiveState, expected.ActiveState)
				}
				if got.SubState != expected.SubState {
					t.Errorf("service %s: SubState = %v, want %v", name, got.SubState, expected.SubState)
				}
			}
		})
	}
}

func TestParseServiceLine(t *testing.T) {
	tests := []struct {
		name     string
		line     string
		expected ServiceState
	}{
		{
			name: "running service",
			line: "nginx.service loaded active running A high performance web server",
			expected: ServiceState{
				Name:        "nginx",
				LoadState:   "loaded",
				ActiveState: "active",
				SubState:    "running",
			},
		},
		{
			name: "stopped service",
			line: "apache2.service loaded inactive dead The Apache HTTP Server",
			expected: ServiceState{
				Name:        "apache2",
				LoadState:   "loaded",
				ActiveState: "inactive",
				SubState:    "dead",
			},
		},
		{
			name: "failed service",
			line: "mysql.service loaded failed failed MySQL Community Server",
			expected: ServiceState{
				Name:        "mysql",
				LoadState:   "loaded",
				ActiveState: "failed",
				SubState:    "failed",
			},
		},
		{
			name: "activating service",
			line: "slow-starter.service loaded activating start Starting Slow Service...",
			expected: ServiceState{
				Name:        "slow-starter",
				LoadState:   "loaded",
				ActiveState: "activating",
				SubState:    "start",
			},
		},
		{
			name:     "too few fields",
			line:     "nginx.service loaded",
			expected: ServiceState{},
		},
		{
			name:     "empty line",
			line:     "",
			expected: ServiceState{},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result := parseServiceLine(tt.line)

			if result.Name != tt.expected.Name {
				t.Errorf("Name = %v, want %v", result.Name, tt.expected.Name)
			}
			if result.LoadState != tt.expected.LoadState {
				t.Errorf("LoadState = %v, want %v", result.LoadState, tt.expected.LoadState)
			}
			if result.ActiveState != tt.expected.ActiveState {
				t.Errorf("ActiveState = %v, want %v", result.ActiveState, tt.expected.ActiveState)
			}
			if result.SubState != tt.expected.SubState {
				t.Errorf("SubState = %v, want %v", result.SubState, tt.expected.SubState)
			}
		})
	}
}

func TestParseUnitFileOutput(t *testing.T) {
	tests := []struct {
		name     string
		output   string
		expected map[string]string
	}{
		{
			name: "mixed unit file states",
			output: `nginx.service                          enabled         enabled
ssh.service                            enabled         enabled
apache2.service                        disabled        enabled
mysql.service                          masked          enabled
cron.service                           static          -`,
			expected: map[string]string{
				"nginx":   "enabled",
				"ssh":     "enabled",
				"apache2": "disabled",
				"mysql":   "masked",
				"cron":    "static",
			},
		},
		{
			name:     "empty output",
			output:   "",
			expected: map[string]string{},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result := parseUnitFileOutput(tt.output)

			if len(result) != len(tt.expected) {
				t.Errorf("got %d entries, want %d", len(result), len(tt.expected))
			}

			for name, expected := range tt.expected {
				got, exists := result[name]
				if !exists {
					t.Errorf("missing unit file %s", name)
					continue
				}
				if got != expected {
					t.Errorf("unit %s: state = %v, want %v", name, got, expected)
				}
			}
		})
	}
}

func TestServiceWatcherStateChangeEvents(t *testing.T) {
	tests := []struct {
		name       string
		previous   string
		current    string
		wantType   event.EventType
		wantEvents bool
	}{
		{
			name:       "service started (inactive -> active)",
			previous:   "inactive",
			current:    "active",
			wantType:   event.ServiceStarted,
			wantEvents: true,
		},
		{
			name:       "service started (failed -> active)",
			previous:   "failed",
			current:    "active",
			wantType:   event.ServiceStarted,
			wantEvents: true,
		},
		{
			name:       "service stopped (active -> inactive)",
			previous:   "active",
			current:    "inactive",
			wantType:   event.ServiceStopped,
			wantEvents: true,
		},
		{
			name:       "service failed (active -> failed)",
			previous:   "active",
			current:    "failed",
			wantType:   event.ServiceStopped,
			wantEvents: true,
		},
		{
			name:       "service deactivating (active -> deactivating)",
			previous:   "active",
			current:    "deactivating",
			wantType:   event.ServiceStopped,
			wantEvents: true,
		},
		{
			name:       "no change (active -> active)",
			previous:   "active",
			current:    "active",
			wantEvents: false,
		},
		{
			name:       "no change (inactive -> inactive)",
			previous:   "inactive",
			current:    "inactive",
			wantEvents: false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			w := NewServiceWatcher(ServiceConfig{
				FortressID: "fort_test",
				ServerID:   "srv_test",
			})

			eventType := w.getStateChangeEventType(tt.previous, tt.current)

			if tt.wantEvents {
				if eventType != tt.wantType {
					t.Errorf("getStateChangeEventType(%q, %q) = %v, want %v",
						tt.previous, tt.current, eventType, tt.wantType)
				}
			} else {
				if eventType != "" {
					t.Errorf("getStateChangeEventType(%q, %q) = %v, want empty",
						tt.previous, tt.current, eventType)
				}
			}
		})
	}
}

func TestServiceWatcherEnableChangeEvents(t *testing.T) {
	tests := []struct {
		name       string
		previous   string
		current    string
		wantType   event.EventType
		wantEvents bool
	}{
		{
			name:       "service enabled (disabled -> enabled)",
			previous:   "disabled",
			current:    "enabled",
			wantType:   event.ServiceEnabled,
			wantEvents: true,
		},
		{
			name:       "service enabled (static -> enabled)",
			previous:   "static",
			current:    "enabled",
			wantType:   event.ServiceEnabled,
			wantEvents: true,
		},
		{
			name:       "service disabled (enabled -> disabled)",
			previous:   "enabled",
			current:    "disabled",
			wantType:   event.ServiceDisabled,
			wantEvents: true,
		},
		{
			name:       "service masked (enabled -> masked)",
			previous:   "enabled",
			current:    "masked",
			wantType:   event.ServiceDisabled,
			wantEvents: true,
		},
		{
			name:       "no change (enabled -> enabled)",
			previous:   "enabled",
			current:    "enabled",
			wantEvents: false,
		},
		{
			name:       "no change (disabled -> disabled)",
			previous:   "disabled",
			current:    "disabled",
			wantEvents: false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			w := NewServiceWatcher(ServiceConfig{
				FortressID: "fort_test",
				ServerID:   "srv_test",
			})

			eventType := w.getEnableChangeEventType(tt.previous, tt.current)

			if tt.wantEvents {
				if eventType != tt.wantType {
					t.Errorf("getEnableChangeEventType(%q, %q) = %v, want %v",
						tt.previous, tt.current, eventType, tt.wantType)
				}
			} else {
				if eventType != "" {
					t.Errorf("getEnableChangeEventType(%q, %q) = %v, want empty",
						tt.previous, tt.current, eventType)
				}
			}
		})
	}
}

func TestServiceWatcherCreateEvent(t *testing.T) {
	w := NewServiceWatcher(ServiceConfig{
		FortressID: "fort_test",
		ServerID:   "srv_test",
	})

	e := w.createServiceEvent(event.ServiceStarted, "nginx", "inactive", "active", "enabled")

	if e.Type != event.ServiceStarted {
		t.Errorf("Type = %v, want %v", e.Type, event.ServiceStarted)
	}
	if e.FortressID != "fort_test" {
		t.Errorf("FortressID = %v, want fort_test", e.FortressID)
	}
	if e.ServerID != "srv_test" {
		t.Errorf("ServerID = %v, want srv_test", e.ServerID)
	}

	// Verify payload
	if e.Payload["service_name"] != "nginx" {
		t.Errorf("payload[service_name] = %v, want nginx", e.Payload["service_name"])
	}
	if e.Payload["previous_state"] != "inactive" {
		t.Errorf("payload[previous_state] = %v, want inactive", e.Payload["previous_state"])
	}
	if e.Payload["new_state"] != "active" {
		t.Errorf("payload[new_state] = %v, want active", e.Payload["new_state"])
	}
	if e.Payload["init_system"] != "systemd" {
		t.Errorf("payload[init_system] = %v, want systemd", e.Payload["init_system"])
	}
	if e.Payload["unit_file"] != "enabled" {
		t.Errorf("payload[unit_file] = %v, want enabled", e.Payload["unit_file"])
	}
}

func TestServiceWatcherWithMockCommand(t *testing.T) {
	if runtime.GOOS != "linux" {
		t.Skip("skipping test on non-Linux system: service watcher requires systemd")
	}

	w := NewServiceWatcher(ServiceConfig{
		PollInterval: 50 * time.Millisecond,
		FortressID:   "fort_test",
		ServerID:     "srv_test",
	})

	callCount := 0
	w.commandRunner = func(name string, args ...string) ([]byte, error) {
		callCount++
		if name == "systemctl" && len(args) > 0 {
			switch args[0] {
			case "list-units":
				if callCount <= 2 {
					// Initial state: nginx running
					return []byte("nginx.service loaded active running Nginx"), nil
				}
				// After some time: nginx stopped
				return []byte("nginx.service loaded inactive dead Nginx"), nil
			case "list-unit-files":
				return []byte("nginx.service enabled enabled"), nil
			}
		}
		return nil, nil
	}

	ctx, cancel := context.WithTimeout(context.Background(), 200*time.Millisecond)
	defer cancel()

	ch, err := w.Watch(ctx)
	if err != nil {
		t.Fatalf("Watch() error = %v", err)
	}

	var events []event.Event
	for e := range ch {
		events = append(events, e)
	}

	// We should detect the nginx state change from active to inactive
	foundStopped := false
	for _, e := range events {
		if e.Type == event.ServiceStopped && e.Payload["service_name"] == "nginx" {
			foundStopped = true
			break
		}
	}

	if !foundStopped {
		t.Error("expected to detect nginx service stopped event")
	}
}

func TestServiceWatcherDetectsNewService(t *testing.T) {
	if runtime.GOOS != "linux" {
		t.Skip("skipping test on non-Linux system: service watcher requires systemd")
	}

	w := NewServiceWatcher(ServiceConfig{
		PollInterval: 50 * time.Millisecond,
		FortressID:   "fort_test",
		ServerID:     "srv_test",
	})

	callCount := 0
	w.commandRunner = func(name string, args ...string) ([]byte, error) {
		callCount++
		if name == "systemctl" && len(args) > 0 {
			switch args[0] {
			case "list-units":
				if callCount <= 2 {
					// Initial: only nginx
					return []byte("nginx.service loaded active running Nginx"), nil
				}
				// Later: nginx + mysql
				return []byte(`nginx.service loaded active running Nginx
mysql.service loaded active running MySQL`), nil
			case "list-unit-files":
				return []byte("nginx.service enabled enabled\nmysql.service enabled enabled"), nil
			}
		}
		return nil, nil
	}

	ctx, cancel := context.WithTimeout(context.Background(), 200*time.Millisecond)
	defer cancel()

	ch, err := w.Watch(ctx)
	if err != nil {
		t.Fatalf("Watch() error = %v", err)
	}

	var events []event.Event
	for e := range ch {
		events = append(events, e)
	}

	// We should detect mysql as a new service
	foundCreated := false
	for _, e := range events {
		if e.Type == event.ServiceCreated && e.Payload["service_name"] == "mysql" {
			foundCreated = true
			break
		}
	}

	if !foundCreated {
		t.Error("expected to detect mysql service created event")
	}
}

func TestServiceWatcherDetectsDeletedService(t *testing.T) {
	if runtime.GOOS != "linux" {
		t.Skip("skipping test on non-Linux system: service watcher requires systemd")
	}

	w := NewServiceWatcher(ServiceConfig{
		PollInterval: 50 * time.Millisecond,
		FortressID:   "fort_test",
		ServerID:     "srv_test",
	})

	callCount := 0
	w.commandRunner = func(name string, args ...string) ([]byte, error) {
		callCount++
		if name == "systemctl" && len(args) > 0 {
			switch args[0] {
			case "list-units":
				if callCount <= 2 {
					// Initial: nginx + mysql
					return []byte(`nginx.service loaded active running Nginx
mysql.service loaded active running MySQL`), nil
				}
				// Later: only nginx (mysql removed)
				return []byte("nginx.service loaded active running Nginx"), nil
			case "list-unit-files":
				return []byte("nginx.service enabled enabled"), nil
			}
		}
		return nil, nil
	}

	ctx, cancel := context.WithTimeout(context.Background(), 200*time.Millisecond)
	defer cancel()

	ch, err := w.Watch(ctx)
	if err != nil {
		t.Fatalf("Watch() error = %v", err)
	}

	var events []event.Event
	for e := range ch {
		events = append(events, e)
	}

	// We should detect mysql as deleted
	foundDeleted := false
	for _, e := range events {
		if e.Type == event.ServiceDeleted && e.Payload["service_name"] == "mysql" {
			foundDeleted = true
			break
		}
	}

	if !foundDeleted {
		t.Error("expected to detect mysql service deleted event")
	}
}

func TestServiceWatcherContextCancellation(t *testing.T) {
	w := NewServiceWatcher(ServiceConfig{
		PollInterval: 1 * time.Hour, // Long interval
		FortressID:   "fort_test",
		ServerID:     "srv_test",
	})

	// Mock to avoid actual systemctl calls
	w.commandRunner = func(name string, args ...string) ([]byte, error) {
		return []byte("nginx.service loaded active running Nginx"), nil
	}

	ctx, cancel := context.WithCancel(context.Background())

	ch, err := w.Watch(ctx)
	if err != nil {
		t.Fatalf("Watch() error = %v", err)
	}

	// Allow some time for the goroutine to start
	time.Sleep(10 * time.Millisecond)

	// Cancel context
	cancel()

	// Channel should close
	select {
	case _, ok := <-ch:
		if ok {
			// Drain any remaining events
			for range ch {
			}
		}
	case <-time.After(100 * time.Millisecond):
		t.Error("channel did not close after context cancellation")
	}
}

func TestServiceWatcherDetectsEnableDisable(t *testing.T) {
	if runtime.GOOS != "linux" {
		t.Skip("skipping test on non-Linux system: service watcher requires systemd")
	}

	w := NewServiceWatcher(ServiceConfig{
		PollInterval: 50 * time.Millisecond,
		FortressID:   "fort_test",
		ServerID:     "srv_test",
	})

	callCount := 0
	w.commandRunner = func(name string, args ...string) ([]byte, error) {
		callCount++
		if name == "systemctl" && len(args) > 0 {
			switch args[0] {
			case "list-units":
				return []byte("nginx.service loaded active running Nginx"), nil
			case "list-unit-files":
				if callCount <= 2 {
					// Initial: enabled
					return []byte("nginx.service enabled enabled"), nil
				}
				// Later: disabled
				return []byte("nginx.service disabled enabled"), nil
			}
		}
		return nil, nil
	}

	ctx, cancel := context.WithTimeout(context.Background(), 200*time.Millisecond)
	defer cancel()

	ch, err := w.Watch(ctx)
	if err != nil {
		t.Fatalf("Watch() error = %v", err)
	}

	var events []event.Event
	for e := range ch {
		events = append(events, e)
	}

	// We should detect nginx being disabled
	foundDisabled := false
	for _, e := range events {
		if e.Type == event.ServiceDisabled && e.Payload["service_name"] == "nginx" {
			foundDisabled = true
			break
		}
	}

	if !foundDisabled {
		t.Error("expected to detect nginx service disabled event")
	}
}
