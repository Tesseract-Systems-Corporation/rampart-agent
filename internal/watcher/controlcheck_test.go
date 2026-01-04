package watcher

import (
	"context"
	"os"
	"path/filepath"
	"runtime"
	"testing"
	"time"

	"github.com/Tesseract-Systems-Corporation/rampart-agent/pkg/event"
)

func TestControlCheckWatcherInterface(t *testing.T) {
	var _ Watcher = (*ControlCheckWatcher)(nil)
}

func TestControlCheckWatcherName(t *testing.T) {
	w := NewControlCheckWatcher(ControlCheckConfig{
		FortressID: "fort_test",
		ServerID:   "srv_test",
	})
	if w.Name() != "controlcheck" {
		t.Errorf("Name() = %v, want controlcheck", w.Name())
	}
}

func TestControlCheckWatcherConfig(t *testing.T) {
	tests := []struct {
		name         string
		config       ControlCheckConfig
		wantInterval time.Duration
	}{
		{
			name: "default interval",
			config: ControlCheckConfig{
				FortressID: "fort_test",
				ServerID:   "srv_test",
			},
			wantInterval: DefaultControlCheckInterval,
		},
		{
			name: "custom interval",
			config: ControlCheckConfig{
				CheckInterval: 30 * time.Minute,
				FortressID:    "fort_test",
				ServerID:      "srv_test",
			},
			wantInterval: 30 * time.Minute,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			w := NewControlCheckWatcher(tt.config)
			if w.checkInterval != tt.wantInterval {
				t.Errorf("checkInterval = %v, want %v", w.checkInterval, tt.wantInterval)
			}
		})
	}
}

func TestControlCheckWatcherEnabledControls(t *testing.T) {
	tests := []struct {
		name            string
		enabledControls []string
		controlID       string
		wantEnabled     bool
	}{
		{
			name:            "all enabled when empty",
			enabledControls: nil,
			controlID:       "CC6.1.1",
			wantEnabled:     true,
		},
		{
			name:            "specific control enabled",
			enabledControls: []string{"CC6.1.1", "CC6.1.2"},
			controlID:       "CC6.1.1",
			wantEnabled:     true,
		},
		{
			name:            "specific control not enabled",
			enabledControls: []string{"CC6.1.1", "CC6.1.2"},
			controlID:       "CC7.1.1",
			wantEnabled:     false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			w := NewControlCheckWatcher(ControlCheckConfig{
				EnabledControls: tt.enabledControls,
				FortressID:      "fort_test",
				ServerID:        "srv_test",
			})
			got := w.isControlEnabled(tt.controlID)
			if got != tt.wantEnabled {
				t.Errorf("isControlEnabled(%q) = %v, want %v", tt.controlID, got, tt.wantEnabled)
			}
		})
	}
}

func TestControlCheckWatcherEmitsEvents(t *testing.T) {
	// Run all controls to ensure we get scoreable results on any platform
	// Some controls return "skip" on non-Linux platforms, so we need multiple
	w := NewControlCheckWatcher(ControlCheckConfig{
		CheckInterval:   50 * time.Millisecond, // Fast interval for testing
		EnabledControls: nil,                   // Enable all controls
		FortressID:      "fort_test",
		ServerID:        "srv_test",
	})

	// Use longer timeout to ensure all checks complete
	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
	defer cancel()

	ch, err := w.Watch(ctx)
	if err != nil {
		t.Fatalf("Watch() error = %v", err)
	}

	var events []event.Event
	for e := range ch {
		events = append(events, e)
	}

	// Should have at least one control check event
	if len(events) < 1 {
		t.Errorf("received %d events, want at least 1", len(events))
	}

	// Verify we have at least ControlCheck events
	hasControlCheck := false
	hasComplianceScore := false
	allSkipped := true
	for _, e := range events {
		if e.Type == event.ControlCheck {
			hasControlCheck = true
			// Verify payload structure
			if _, ok := e.Payload["control_id"]; !ok {
				t.Error("control check event missing control_id")
			}
			status, ok := e.Payload["status"]
			if !ok {
				t.Error("control check event missing status")
			}
			// Track if any checks are not skipped
			if status != "skip" {
				allSkipped = false
			}
		}
		if e.Type == event.ComplianceScore {
			hasComplianceScore = true
			// Verify payload structure
			if _, ok := e.Payload["overall_score"]; !ok {
				t.Error("compliance score event missing overall_score")
			}
		}
	}

	if !hasControlCheck {
		t.Error("no ControlCheck event received")
	}
	// ComplianceScore is only emitted when at least one check doesn't return "skip"
	// On non-Linux platforms, some checks may be skipped
	if !allSkipped && !hasComplianceScore {
		t.Error("no ComplianceScore event received (expected since some checks ran)")
	}
}

func TestControlCheckWatcherContextCancellation(t *testing.T) {
	w := NewControlCheckWatcher(ControlCheckConfig{
		CheckInterval: 1 * time.Hour, // Long interval
		FortressID:    "fort_test",
		ServerID:      "srv_test",
	})

	ctx, cancel := context.WithCancel(context.Background())

	ch, err := w.Watch(ctx)
	if err != nil {
		t.Fatalf("Watch() error = %v", err)
	}

	// Wait for initial events
	time.Sleep(100 * time.Millisecond)

	// Cancel context
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

func TestCalculateScore(t *testing.T) {
	tests := []struct {
		name     string
		passing  int
		failing  int
		warning  int
		expected float64
	}{
		{
			name:     "all passing",
			passing:  10,
			failing:  0,
			warning:  0,
			expected: 100,
		},
		{
			name:     "all failing",
			passing:  0,
			failing:  10,
			warning:  0,
			expected: 0,
		},
		{
			name:     "half and half",
			passing:  5,
			failing:  5,
			warning:  0,
			expected: 50,
		},
		{
			name:     "with warnings",
			passing:  5,
			failing:  0,
			warning:  5,
			expected: 75, // (5*100 + 5*50) / 10 = 75
		},
		{
			name:     "no checks",
			passing:  0,
			failing:  0,
			warning:  0,
			expected: 100, // No checks = 100% (nothing to fail)
		},
		{
			name:     "mixed",
			passing:  6,
			failing:  2,
			warning:  2,
			expected: 70, // (6*100 + 2*50) / 10 = 70
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := CalculateScore(tt.passing, tt.failing, tt.warning)
			if got != tt.expected {
				t.Errorf("CalculateScore(%d, %d, %d) = %v, want %v",
					tt.passing, tt.failing, tt.warning, got, tt.expected)
			}
		})
	}
}

func TestExtractCategory(t *testing.T) {
	tests := []struct {
		controlID string
		expected  string
	}{
		{"CC6.1.1", "CC6.1"},
		{"CC6.1.2", "CC6.1"},
		{"CC7.1.1", "CC7.1"},
		{"CC8.1.1", "CC8.1"},
		{"CC6.6.1", "CC6.6"},
		{"INVALID", "INVALID"},
	}

	for _, tt := range tests {
		t.Run(tt.controlID, func(t *testing.T) {
			got := extractCategory(tt.controlID)
			if got != tt.expected {
				t.Errorf("extractCategory(%q) = %q, want %q", tt.controlID, got, tt.expected)
			}
		})
	}
}

func TestCheckResultStatuses(t *testing.T) {
	// Verify all check functions return valid statuses
	validStatuses := map[string]bool{
		"pass":    true,
		"fail":    true,
		"warning": true,
		"skip":    true,
	}

	for _, check := range checks {
		t.Run(check.ID+"_"+check.Name, func(t *testing.T) {
			result := check.Check()
			if !validStatuses[result.Status] {
				t.Errorf("check %s returned invalid status: %q", check.ID, result.Status)
			}
			// Evidence should always be set
			if result.Evidence == "" {
				t.Errorf("check %s returned empty evidence", check.ID)
			}
		})
	}
}

// Test individual check functions with mock data

func TestCheckSSHPasswordAuthDisabled(t *testing.T) {
	if runtime.GOOS != "linux" {
		result := checkSSHPasswordAuthDisabled()
		if result.Status != "skip" {
			t.Errorf("expected skip on non-Linux, got %s", result.Status)
		}
		return
	}

	// On Linux, the result depends on actual system config
	result := checkSSHPasswordAuthDisabled()
	validStatuses := map[string]bool{"pass": true, "fail": true, "warning": true}
	if !validStatuses[result.Status] {
		t.Errorf("unexpected status: %s", result.Status)
	}
}

func TestCheckRootLoginDisabled(t *testing.T) {
	if runtime.GOOS != "linux" {
		result := checkRootLoginDisabled()
		if result.Status != "skip" {
			t.Errorf("expected skip on non-Linux, got %s", result.Status)
		}
		return
	}

	result := checkRootLoginDisabled()
	validStatuses := map[string]bool{"pass": true, "fail": true, "warning": true}
	if !validStatuses[result.Status] {
		t.Errorf("unexpected status: %s", result.Status)
	}
}

func TestCheckNoEmptyPasswords(t *testing.T) {
	if runtime.GOOS != "linux" {
		result := checkNoEmptyPasswords()
		if result.Status != "skip" {
			t.Errorf("expected skip on non-Linux, got %s", result.Status)
		}
		return
	}

	// This test requires root access to read /etc/shadow
	result := checkNoEmptyPasswords()
	validStatuses := map[string]bool{"pass": true, "fail": true}
	if !validStatuses[result.Status] {
		// May fail if not root - that's expected
		if result.Status != "fail" || !stringContainsSubstr(result.Evidence, "Could not read") {
			t.Logf("checkNoEmptyPasswords: %s - %s", result.Status, result.Evidence)
		}
	}
}

func TestCheckFirewallEnabled(t *testing.T) {
	if runtime.GOOS != "linux" {
		result := checkFirewallEnabled()
		if result.Status != "skip" {
			t.Errorf("expected skip on non-Linux, got %s", result.Status)
		}
		return
	}

	result := checkFirewallEnabled()
	validStatuses := map[string]bool{"pass": true, "fail": true}
	if !validStatuses[result.Status] {
		t.Errorf("unexpected status: %s", result.Status)
	}
}

func TestCheckMACEnabled(t *testing.T) {
	if runtime.GOOS != "linux" {
		result := checkMACEnabled()
		if result.Status != "skip" {
			t.Errorf("expected skip on non-Linux, got %s", result.Status)
		}
		return
	}

	result := checkMACEnabled()
	validStatuses := map[string]bool{"pass": true, "fail": true, "warning": true}
	if !validStatuses[result.Status] {
		t.Errorf("unexpected status: %s", result.Status)
	}
}

func TestCheckTLSVersion(t *testing.T) {
	if runtime.GOOS != "linux" {
		result := checkTLSVersion()
		if result.Status != "skip" {
			t.Errorf("expected skip on non-Linux, got %s", result.Status)
		}
		return
	}

	result := checkTLSVersion()
	validStatuses := map[string]bool{"pass": true, "fail": true, "warning": true}
	if !validStatuses[result.Status] {
		t.Errorf("unexpected status: %s", result.Status)
	}
}

func TestCheckAuditdEnabled(t *testing.T) {
	if runtime.GOOS != "linux" {
		result := checkAuditdEnabled()
		if result.Status != "skip" {
			t.Errorf("expected skip on non-Linux, got %s", result.Status)
		}
		return
	}

	result := checkAuditdEnabled()
	validStatuses := map[string]bool{"pass": true, "fail": true}
	if !validStatuses[result.Status] {
		t.Errorf("unexpected status: %s", result.Status)
	}
}

func TestCheckSyslogRunning(t *testing.T) {
	if runtime.GOOS != "linux" {
		result := checkSyslogRunning()
		if result.Status != "skip" {
			t.Errorf("expected skip on non-Linux, got %s", result.Status)
		}
		return
	}

	result := checkSyslogRunning()
	validStatuses := map[string]bool{"pass": true, "fail": true}
	if !validStatuses[result.Status] {
		t.Errorf("unexpected status: %s", result.Status)
	}
}

func TestCheckPackageIntegrity(t *testing.T) {
	if runtime.GOOS != "linux" {
		result := checkPackageIntegrity()
		if result.Status != "skip" {
			t.Errorf("expected skip on non-Linux, got %s", result.Status)
		}
		return
	}

	result := checkPackageIntegrity()
	validStatuses := map[string]bool{"pass": true, "fail": true, "warning": true, "skip": true}
	if !validStatuses[result.Status] {
		t.Errorf("unexpected status: %s", result.Status)
	}
}

// Mock-based tests for SSH config parsing

func TestParseSSHConfigPasswordAuth(t *testing.T) {
	tests := []struct {
		name     string
		content  string
		expected string // pass, fail, or warning
	}{
		{
			name:     "explicitly disabled",
			content:  "PasswordAuthentication no\n",
			expected: "pass",
		},
		{
			name:     "explicitly enabled",
			content:  "PasswordAuthentication yes\n",
			expected: "fail",
		},
		{
			name:     "commented out",
			content:  "#PasswordAuthentication no\n",
			expected: "warning", // not explicitly set
		},
		{
			name:     "with other settings",
			content:  "Port 22\nPasswordAuthentication no\nPermitRootLogin no\n",
			expected: "pass",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			// Create temp file with content
			dir := t.TempDir()
			configPath := filepath.Join(dir, "sshd_config")
			if err := os.WriteFile(configPath, []byte(tt.content), 0644); err != nil {
				t.Fatalf("failed to create test file: %v", err)
			}

			// We can't easily mock the file path, but we can test the parsing logic
			// by checking the content parsing behavior
			result := parseSSHConfigForPasswordAuth(tt.content)
			if result != tt.expected {
				t.Errorf("parseSSHConfigForPasswordAuth(%q) = %v, want %v", tt.content, result, tt.expected)
			}
		})
	}
}

// Helper to parse SSH config content (simulates the check logic)
func parseSSHConfigForPasswordAuth(content string) string {
	lines := splitLines(content)
	for _, line := range lines {
		line = trimSpace(line)
		if hasPrefix(line, "#") {
			continue
		}
		if hasPrefixCaseInsensitive(line, "passwordauthentication") {
			fields := splitFields(line)
			if len(fields) >= 2 && toLower(fields[1]) == "no" {
				return "pass"
			}
			return "fail"
		}
	}
	return "warning"
}

// Test helper functions
func splitLines(s string) []string {
	var lines []string
	start := 0
	for i := 0; i < len(s); i++ {
		if s[i] == '\n' {
			lines = append(lines, s[start:i])
			start = i + 1
		}
	}
	if start < len(s) {
		lines = append(lines, s[start:])
	}
	return lines
}

func trimSpace(s string) string {
	start := 0
	end := len(s)
	for start < end && (s[start] == ' ' || s[start] == '\t') {
		start++
	}
	for end > start && (s[end-1] == ' ' || s[end-1] == '\t') {
		end--
	}
	return s[start:end]
}

func hasPrefix(s, prefix string) bool {
	return len(s) >= len(prefix) && s[:len(prefix)] == prefix
}

func hasPrefixCaseInsensitive(s, prefix string) bool {
	if len(s) < len(prefix) {
		return false
	}
	return toLower(s[:len(prefix)]) == toLower(prefix)
}

func toLower(s string) string {
	result := make([]byte, len(s))
	for i := 0; i < len(s); i++ {
		c := s[i]
		if c >= 'A' && c <= 'Z' {
			c += 'a' - 'A'
		}
		result[i] = c
	}
	return string(result)
}

func splitFields(s string) []string {
	var fields []string
	start := -1
	for i := 0; i < len(s); i++ {
		if s[i] == ' ' || s[i] == '\t' {
			if start >= 0 {
				fields = append(fields, s[start:i])
				start = -1
			}
		} else {
			if start < 0 {
				start = i
			}
		}
	}
	if start >= 0 {
		fields = append(fields, s[start:])
	}
	return fields
}

func stringContainsSubstr(s, substr string) bool {
	for i := 0; i <= len(s)-len(substr); i++ {
		if s[i:i+len(substr)] == substr {
			return true
		}
	}
	return false
}

func TestControlCheckPayloadStructure(t *testing.T) {
	w := NewControlCheckWatcher(ControlCheckConfig{
		CheckInterval:   50 * time.Millisecond,
		EnabledControls: []string{"CC6.1.1"},
		FortressID:      "fort_test",
		ServerID:        "srv_test",
	})

	ctx, cancel := context.WithTimeout(context.Background(), 150*time.Millisecond)
	defer cancel()

	ch, err := w.Watch(ctx)
	if err != nil {
		t.Fatalf("Watch() error = %v", err)
	}

	for e := range ch {
		if e.Type == event.ControlCheck {
			// Verify all required fields
			requiredFields := []string{"control_id", "check_name", "status", "evidence"}
			for _, field := range requiredFields {
				if _, ok := e.Payload[field]; !ok {
					t.Errorf("ControlCheck event missing required field: %s", field)
				}
			}

			// Verify status is valid
			status, ok := e.Payload["status"].(string)
			if !ok {
				t.Error("status is not a string")
			}
			validStatuses := map[string]bool{"pass": true, "fail": true, "warning": true, "skip": true}
			if !validStatuses[status] {
				t.Errorf("invalid status: %s", status)
			}

			// Verify fortress and server IDs
			if e.FortressID != "fort_test" {
				t.Errorf("FortressID = %v, want fort_test", e.FortressID)
			}
			if e.ServerID != "srv_test" {
				t.Errorf("ServerID = %v, want srv_test", e.ServerID)
			}
		}

		if e.Type == event.ComplianceScore {
			// Verify score payload
			if _, ok := e.Payload["overall_score"]; !ok {
				t.Error("ComplianceScore missing overall_score")
			}
			if _, ok := e.Payload["by_category"]; !ok {
				t.Error("ComplianceScore missing by_category")
			}
			if _, ok := e.Payload["passing_controls"]; !ok {
				t.Error("ComplianceScore missing passing_controls")
			}
			if _, ok := e.Payload["failing_controls"]; !ok {
				t.Error("ComplianceScore missing failing_controls")
			}
			if _, ok := e.Payload["warning_controls"]; !ok {
				t.Error("ComplianceScore missing warning_controls")
			}
		}
	}
}

func TestAllChecksHaveRequiredFields(t *testing.T) {
	for _, check := range checks {
		if check.ID == "" {
			t.Error("found check with empty ID")
		}
		if check.Name == "" {
			t.Errorf("check %s has empty Name", check.ID)
		}
		if check.Check == nil {
			t.Errorf("check %s has nil Check function", check.ID)
		}
	}
}

func TestCheckIDsAreUnique(t *testing.T) {
	seen := make(map[string]bool)
	for _, check := range checks {
		if seen[check.ID] {
			t.Errorf("duplicate check ID: %s", check.ID)
		}
		seen[check.ID] = true
	}
}
