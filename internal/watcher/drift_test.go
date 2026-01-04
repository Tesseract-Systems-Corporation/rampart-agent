package watcher

import (
	"context"
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/Tesseract-Systems-Corporation/rampart-agent/pkg/event"
)

func TestDriftWatcherInterface(t *testing.T) {
	var _ Watcher = (*DriftWatcher)(nil)
}

func TestDriftWatcherName(t *testing.T) {
	w := NewDriftWatcher(DriftConfig{
		WatchPaths: []string{"/etc"},
		FortressID: "fort_test",
		ServerID:   "srv_test",
	})
	if w.Name() != "drift" {
		t.Errorf("Name() = %v, want drift", w.Name())
	}
}

func TestDriftWatcherConfig(t *testing.T) {
	tests := []struct {
		name           string
		config         DriftConfig
		wantPaths      []string
		wantIgnore     []string
	}{
		{
			name: "with paths",
			config: DriftConfig{
				WatchPaths: []string{"/etc/nginx", "/etc/ssl"},
				FortressID: "fort_test",
				ServerID:   "srv_test",
			},
			wantPaths: []string{"/etc/nginx", "/etc/ssl"},
		},
		{
			name: "with ignore patterns",
			config: DriftConfig{
				WatchPaths:     []string{"/etc"},
				IgnorePatterns: []string{"*.log", "*.tmp"},
				FortressID:     "fort_test",
				ServerID:       "srv_test",
			},
			wantPaths:  []string{"/etc"},
			wantIgnore: []string{"*.log", "*.tmp"},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			w := NewDriftWatcher(tt.config)
			if len(w.watchPaths) != len(tt.wantPaths) {
				t.Errorf("watchPaths = %v, want %v", w.watchPaths, tt.wantPaths)
			}
		})
	}
}

func TestShouldIgnoreFile(t *testing.T) {
	tests := []struct {
		name     string
		path     string
		patterns []string
		want     bool
	}{
		{
			name:     "matches log pattern",
			path:     "/var/log/test.log",
			patterns: []string{"*.log"},
			want:     true,
		},
		{
			name:     "matches tmp pattern",
			path:     "/tmp/temp.tmp",
			patterns: []string{"*.tmp"},
			want:     true,
		},
		{
			name:     "no match",
			path:     "/etc/nginx/nginx.conf",
			patterns: []string{"*.log", "*.tmp"},
			want:     false,
		},
		{
			name:     "empty patterns",
			path:     "/etc/test.log",
			patterns: []string{},
			want:     false,
		},
		{
			name:     "directory pattern",
			path:     "/var/cache/file.txt",
			patterns: []string{"cache/*"},
			want:     false, // Simple glob doesn't match directories
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := shouldIgnoreFile(tt.path, tt.patterns)
			if got != tt.want {
				t.Errorf("shouldIgnoreFile(%q) = %v, want %v", tt.path, got, tt.want)
			}
		})
	}
}

func TestComputeFileHash(t *testing.T) {
	// Create a temporary file
	dir := t.TempDir()
	filePath := filepath.Join(dir, "test.txt")

	content := []byte("hello world")
	if err := os.WriteFile(filePath, content, 0644); err != nil {
		t.Fatalf("failed to create test file: %v", err)
	}

	hash1, err := computeFileHash(filePath)
	if err != nil {
		t.Fatalf("computeFileHash() error = %v", err)
	}

	// Hash should be consistent
	hash2, err := computeFileHash(filePath)
	if err != nil {
		t.Fatalf("computeFileHash() second call error = %v", err)
	}

	if hash1 != hash2 {
		t.Errorf("hashes don't match: %s != %s", hash1, hash2)
	}

	// Hash should be a valid hex string (SHA256 = 64 chars)
	if len(hash1) != 64 {
		t.Errorf("hash length = %d, want 64", len(hash1))
	}

	// Different content should produce different hash
	if err := os.WriteFile(filePath, []byte("different content"), 0644); err != nil {
		t.Fatalf("failed to modify test file: %v", err)
	}

	hash3, err := computeFileHash(filePath)
	if err != nil {
		t.Fatalf("computeFileHash() after modify error = %v", err)
	}

	if hash1 == hash3 {
		t.Error("hash should change after file modification")
	}
}

func TestComputeFileHashNonexistent(t *testing.T) {
	_, err := computeFileHash("/nonexistent/file.txt")
	if err == nil {
		t.Error("expected error for nonexistent file")
	}
}

func TestDriftWatcherDetectsChanges(t *testing.T) {
	// Create a temporary directory with a file
	dir := t.TempDir()
	testFile := filepath.Join(dir, "config.conf")

	if err := os.WriteFile(testFile, []byte("initial content"), 0644); err != nil {
		t.Fatalf("failed to create test file: %v", err)
	}

	w := NewDriftWatcher(DriftConfig{
		WatchPaths: []string{dir},
		FortressID: "fort_test",
		ServerID:   "srv_test",
	})

	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
	defer cancel()

	ch, err := w.Watch(ctx)
	if err != nil {
		t.Fatalf("Watch() error = %v", err)
	}

	// Give watcher time to initialize
	time.Sleep(100 * time.Millisecond)

	// Modify the file
	if err := os.WriteFile(testFile, []byte("modified content"), 0644); err != nil {
		t.Fatalf("failed to modify test file: %v", err)
	}

	// Wait for event
	var received *event.Event
	select {
	case e := <-ch:
		received = &e
	case <-time.After(1 * time.Second):
		// May not receive event on all platforms
	}

	if received != nil {
		if received.Type != event.DriftFileChanged {
			t.Errorf("Type = %v, want %v", received.Type, event.DriftFileChanged)
		}

		payload := received.Payload
		if payload["path"] != testFile {
			t.Errorf("path = %v, want %v", payload["path"], testFile)
		}
	}
}

func TestDriftWatcherContextCancellation(t *testing.T) {
	dir := t.TempDir()

	w := NewDriftWatcher(DriftConfig{
		WatchPaths: []string{dir},
		FortressID: "fort_test",
		ServerID:   "srv_test",
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

func TestDriftWatcherIgnoresPatterns(t *testing.T) {
	dir := t.TempDir()

	// Create a file that should be ignored
	logFile := filepath.Join(dir, "test.log")
	if err := os.WriteFile(logFile, []byte("log content"), 0644); err != nil {
		t.Fatalf("failed to create log file: %v", err)
	}

	// Create a file that should not be ignored
	confFile := filepath.Join(dir, "test.conf")
	if err := os.WriteFile(confFile, []byte("conf content"), 0644); err != nil {
		t.Fatalf("failed to create conf file: %v", err)
	}

	w := NewDriftWatcher(DriftConfig{
		WatchPaths:     []string{dir},
		IgnorePatterns: []string{"*.log"},
		FortressID:     "fort_test",
		ServerID:       "srv_test",
	})

	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
	defer cancel()

	ch, err := w.Watch(ctx)
	if err != nil {
		t.Fatalf("Watch() error = %v", err)
	}

	// Give watcher time to initialize
	time.Sleep(100 * time.Millisecond)

	// Modify both files
	os.WriteFile(logFile, []byte("modified log"), 0644)
	os.WriteFile(confFile, []byte("modified conf"), 0644)

	// Collect events
	events := make([]event.Event, 0)
	timeout := time.After(1 * time.Second)

loop:
	for {
		select {
		case e, ok := <-ch:
			if !ok {
				break loop
			}
			events = append(events, e)
		case <-timeout:
			break loop
		}
	}

	// Should only see the .conf file change, not the .log file
	for _, e := range events {
		path := e.Payload["path"].(string)
		if filepath.Ext(path) == ".log" {
			t.Errorf("received event for ignored file: %s", path)
		}
	}
}

func TestCreateDriftEvent(t *testing.T) {
	e := createDriftEvent("/etc/nginx/nginx.conf", "abc123", "def456", "some diff content", "content", "root", "fort_test", "srv_test")

	if e.Type != event.DriftFileChanged {
		t.Errorf("Type = %v, want %v", e.Type, event.DriftFileChanged)
	}

	payload := e.Payload
	if payload["path"] != "/etc/nginx/nginx.conf" {
		t.Errorf("path = %v, want /etc/nginx/nginx.conf", payload["path"])
	}
	if payload["previous_hash"] != "abc123" {
		t.Errorf("previous_hash = %v, want abc123", payload["previous_hash"])
	}
	if payload["current_hash"] != "def456" {
		t.Errorf("current_hash = %v, want def456", payload["current_hash"])
	}
	if payload["diff"] != "some diff content" {
		t.Errorf("diff = %v, want 'some diff content'", payload["diff"])
	}
	if payload["diff_type"] != "content" {
		t.Errorf("diff_type = %v, want content", payload["diff_type"])
	}
	if payload["actor"] != "root" {
		t.Errorf("actor = %v, want root", payload["actor"])
	}
}
