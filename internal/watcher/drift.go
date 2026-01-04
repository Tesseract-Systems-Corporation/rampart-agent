package watcher

import (
	"bufio"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"io"
	"log/slog"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"sync"

	"github.com/fsnotify/fsnotify"
	"github.com/Tesseract-Systems-Corporation/rampart-agent/pkg/event"
)

const (
	// MaxDiffFileSize is the max file size to compute diffs for (64KB)
	MaxDiffFileSize = 64 * 1024
	// MaxDiffLines is the max lines to include in diff output
	MaxDiffLines = 100
)

// DriftConfig holds configuration for the Drift watcher.
type DriftConfig struct {
	// WatchPaths is a list of directories or files to watch.
	WatchPaths []string

	// IgnorePatterns is a list of glob patterns to ignore.
	IgnorePatterns []string

	// FortressID is the ID of the Fortress this agent belongs to.
	FortressID string

	// ServerID is the ID of this server.
	ServerID string

	// Logger is the logger to use. If nil, uses slog.Default().
	Logger *slog.Logger
}

// DriftWatcher monitors file system changes for drift detection.
type DriftWatcher struct {
	watchPaths     []string
	ignorePatterns []string
	fortressID     string
	serverID       string
	logger         *slog.Logger

	// hashes stores the last known hash of each watched file
	hashes map[string]string
	// contents stores the last known content of each watched file (for diff)
	contents map[string]string
	mu       sync.RWMutex
}

// NewDriftWatcher creates a new DriftWatcher with the given configuration.
func NewDriftWatcher(cfg DriftConfig) *DriftWatcher {
	logger := cfg.Logger
	if logger == nil {
		logger = slog.Default()
	}

	return &DriftWatcher{
		watchPaths:     cfg.WatchPaths,
		ignorePatterns: cfg.IgnorePatterns,
		fortressID:     cfg.FortressID,
		serverID:       cfg.ServerID,
		logger:         logger,
		hashes:         make(map[string]string),
		contents:       make(map[string]string),
	}
}

// Watch starts watching for file changes and returns a channel of events.
func (w *DriftWatcher) Watch(ctx context.Context) (<-chan event.Event, error) {
	out := make(chan event.Event)

	watcher, err := fsnotify.NewWatcher()
	if err != nil {
		return nil, err
	}

	go func() {
		defer close(out)
		defer watcher.Close()

		w.logger.Info("starting drift watcher", "paths", w.watchPaths)

		// Add all watch paths
		for _, path := range w.watchPaths {
			if err := w.addWatchPath(watcher, path); err != nil {
				w.logger.Error("failed to add watch path", "path", path, "error", err)
			}
		}

		// Initialize hashes for existing files
		w.initializeHashes()

		for {
			select {
			case <-ctx.Done():
				w.logger.Info("drift watcher stopped", "reason", ctx.Err())
				return

			case ev, ok := <-watcher.Events:
				if !ok {
					return
				}
				w.handleEvent(ctx, out, ev)

			case err, ok := <-watcher.Errors:
				if !ok {
					return
				}
				w.logger.Error("fsnotify error", "error", err)
			}
		}
	}()

	return out, nil
}

// Name returns the watcher name.
func (w *DriftWatcher) Name() string {
	return "drift"
}

// addWatchPath adds a path (file or directory) to the watcher.
func (w *DriftWatcher) addWatchPath(watcher *fsnotify.Watcher, path string) error {
	info, err := os.Stat(path)
	if err != nil {
		return err
	}

	if info.IsDir() {
		// Walk directory and add all subdirectories
		return filepath.WalkDir(path, func(p string, d os.DirEntry, err error) error {
			if err != nil {
				return err
			}
			if d.IsDir() {
				return watcher.Add(p)
			}
			return nil
		})
	}

	// Single file
	return watcher.Add(filepath.Dir(path))
}

// initializeHashes computes and stores hashes for all files in watched paths.
func (w *DriftWatcher) initializeHashes() {
	w.mu.Lock()
	defer w.mu.Unlock()

	for _, path := range w.watchPaths {
		filepath.WalkDir(path, func(p string, d os.DirEntry, err error) error {
			if err != nil {
				return nil
			}
			if d.IsDir() {
				return nil
			}
			if shouldIgnoreFile(p, w.ignorePatterns) {
				return nil
			}

			hash, err := computeFileHash(p)
			if err == nil {
				w.hashes[p] = hash
			}

			// Store content for diff (only for small text files)
			content, err := readFileContent(p)
			if err == nil {
				w.contents[p] = content
			}
			return nil
		})
	}
}

// handleEvent processes a fsnotify event.
func (w *DriftWatcher) handleEvent(ctx context.Context, out chan<- event.Event, ev fsnotify.Event) {
	// Only care about writes and creates
	if !ev.Has(fsnotify.Write) && !ev.Has(fsnotify.Create) {
		return
	}

	path := ev.Name

	// Check if we should ignore this file
	if shouldIgnoreFile(path, w.ignorePatterns) {
		return
	}

	// Check if it's a regular file
	info, err := os.Stat(path)
	if err != nil || info.IsDir() {
		return
	}

	// Compute new hash
	newHash, err := computeFileHash(path)
	if err != nil {
		w.logger.Error("failed to compute hash", "path", path, "error", err)
		return
	}

	// Compare with previous hash
	w.mu.RLock()
	oldHash, existed := w.hashes[path]
	oldContent := w.contents[path]
	w.mu.RUnlock()

	if existed && oldHash == newHash {
		// No actual change
		return
	}

	// Read new content for diff
	newContent, readErr := readFileContent(path)
	if readErr != nil {
		w.logger.Debug("could not read file content for diff", "path", path, "error", readErr)
	}

	// Compute diff
	var diff string
	var diffType string
	if oldContent != "" && newContent != "" {
		// Have both old and new - compute proper diff
		diff = computeUnifiedDiff(path, oldContent, newContent)
		diffType = "unified"
	} else if newContent != "" && oldContent == "" {
		// New file or no previous content - show all lines as added
		diff = formatNewFile(newContent)
		diffType = "new_file"
	} else if newContent == "" && oldContent != "" {
		// File was deleted or became unreadable
		diff = formatDeletedFile(oldContent)
		diffType = "deleted"
	} else if newContent == "" && readErr != nil {
		// Could not read content - indicate why
		diff = fmt.Sprintf("Could not read file content: %v", readErr)
		diffType = "error"
	}

	// Update stored hash and content
	w.mu.Lock()
	w.hashes[path] = newHash
	if newContent != "" {
		w.contents[path] = newContent
	}
	w.mu.Unlock()

	// Get the user who likely made this change
	actor := detectActor()

	// Emit drift event
	w.logger.Info("file drift detected",
		"path", path,
		"previous_hash", oldHash,
		"current_hash", newHash,
		"actor", actor,
	)

	e := createDriftEvent(path, oldHash, newHash, diff, diffType, actor, w.fortressID, w.serverID)
	select {
	case <-ctx.Done():
	case out <- e:
	}
}

// shouldIgnoreFile checks if a file matches any ignore pattern.
func shouldIgnoreFile(path string, patterns []string) bool {
	for _, pattern := range patterns {
		// Match against just the filename
		matched, _ := filepath.Match(pattern, filepath.Base(path))
		if matched {
			return true
		}
	}
	return false
}

// computeFileHash computes the SHA256 hash of a file.
func computeFileHash(path string) (string, error) {
	file, err := os.Open(path)
	if err != nil {
		return "", err
	}
	defer file.Close()

	h := sha256.New()
	if _, err := io.Copy(h, file); err != nil {
		return "", err
	}

	return hex.EncodeToString(h.Sum(nil)), nil
}

// createDriftEvent creates a drift event.
func createDriftEvent(path, previousHash, currentHash, diff, diffType, actor, fortressID, serverID string) event.Event {
	return event.NewEvent(event.DriftFileChanged, fortressID, serverID, map[string]any{
		"path":          path,
		"previous_hash": previousHash,
		"current_hash":  currentHash,
		"diff":          diff,
		"diff_type":     diffType,
		"actor":         actor,
	})
}

// readFileContent reads file content if it's small enough for diffing.
func readFileContent(path string) (string, error) {
	info, err := os.Stat(path)
	if err != nil {
		return "", err
	}

	// Skip files that are too large
	if info.Size() > MaxDiffFileSize {
		return "", fmt.Errorf("file too large for diff: %d bytes", info.Size())
	}

	// Check if it's likely a text file (simple heuristic)
	file, err := os.Open(path)
	if err != nil {
		return "", err
	}
	defer file.Close()

	// Read first 512 bytes to check for binary content
	buf := make([]byte, 512)
	n, err := file.Read(buf)
	if err != nil && err != io.EOF {
		return "", err
	}

	// Check for null bytes (binary indicator)
	for i := 0; i < n; i++ {
		if buf[i] == 0 {
			return "", fmt.Errorf("binary file detected")
		}
	}

	// Seek back and read full content
	file.Seek(0, 0)
	content, err := io.ReadAll(file)
	if err != nil {
		return "", err
	}

	return string(content), nil
}

// computeUnifiedDiff computes a unified diff between old and new content.
func computeUnifiedDiff(path, oldContent, newContent string) string {
	oldLines := strings.Split(oldContent, "\n")
	newLines := strings.Split(newContent, "\n")

	// Simple line-by-line diff (not a full Myers diff, but sufficient for small files)
	var result strings.Builder
	result.WriteString(fmt.Sprintf("--- a/%s\n", filepath.Base(path)))
	result.WriteString(fmt.Sprintf("+++ b/%s\n", filepath.Base(path)))

	// Find common prefix
	commonPrefix := 0
	for commonPrefix < len(oldLines) && commonPrefix < len(newLines) {
		if oldLines[commonPrefix] != newLines[commonPrefix] {
			break
		}
		commonPrefix++
	}

	// Find common suffix
	commonSuffix := 0
	for commonSuffix < len(oldLines)-commonPrefix && commonSuffix < len(newLines)-commonPrefix {
		if oldLines[len(oldLines)-1-commonSuffix] != newLines[len(newLines)-1-commonSuffix] {
			break
		}
		commonSuffix++
	}

	// Extract changed region
	oldStart := commonPrefix
	oldEnd := len(oldLines) - commonSuffix
	newStart := commonPrefix
	newEnd := len(newLines) - commonSuffix

	// If no changes, return empty
	if oldStart >= oldEnd && newStart >= newEnd {
		return ""
	}

	// Context lines before change
	contextStart := oldStart - 3
	if contextStart < 0 {
		contextStart = 0
	}

	// Context lines after change
	contextEnd := oldEnd + 3
	if contextEnd > len(oldLines) {
		contextEnd = len(oldLines)
	}

	// Write hunk header
	oldHunkSize := oldEnd - oldStart
	newHunkSize := newEnd - newStart
	result.WriteString(fmt.Sprintf("@@ -%d,%d +%d,%d @@\n", oldStart+1, oldHunkSize+6, newStart+1, newHunkSize+6))

	// Write context before
	for i := contextStart; i < oldStart; i++ {
		result.WriteString(fmt.Sprintf(" %s\n", oldLines[i]))
	}

	// Write removed lines
	for i := oldStart; i < oldEnd; i++ {
		result.WriteString(fmt.Sprintf("-%s\n", oldLines[i]))
	}

	// Write added lines
	for i := newStart; i < newEnd; i++ {
		result.WriteString(fmt.Sprintf("+%s\n", newLines[i]))
	}

	// Write context after
	for i := oldEnd; i < contextEnd && i < len(oldLines); i++ {
		result.WriteString(fmt.Sprintf(" %s\n", oldLines[i]))
	}

	// Limit output
	lines := strings.Split(result.String(), "\n")
	if len(lines) > MaxDiffLines {
		lines = lines[:MaxDiffLines]
		lines = append(lines, fmt.Sprintf("... (%d more lines)", len(lines)-MaxDiffLines))
	}

	return strings.Join(lines, "\n")
}

// formatNewFile formats content for a new file (all lines added).
func formatNewFile(content string) string {
	lines := strings.Split(content, "\n")
	var result strings.Builder
	result.WriteString("@@ -0,0 +1," + fmt.Sprintf("%d", len(lines)) + " @@\n")

	count := 0
	for _, line := range lines {
		if count >= MaxDiffLines {
			result.WriteString(fmt.Sprintf("... (%d more lines)\n", len(lines)-count))
			break
		}
		result.WriteString(fmt.Sprintf("+%s\n", line))
		count++
	}

	return result.String()
}

// formatDeletedFile formats content for a deleted file (all lines removed).
func formatDeletedFile(content string) string {
	lines := strings.Split(content, "\n")
	var result strings.Builder
	result.WriteString("@@ -1," + fmt.Sprintf("%d", len(lines)) + " +0,0 @@\n")

	count := 0
	for _, line := range lines {
		if count >= MaxDiffLines {
			result.WriteString(fmt.Sprintf("... (%d more lines)\n", len(lines)-count))
			break
		}
		result.WriteString(fmt.Sprintf("-%s\n", line))
		count++
	}

	return result.String()
}

// detectActor attempts to identify who made the file change.
func detectActor() string {
	// Method 1: Check who is currently logged in via SSH
	// Parse /var/log/auth.log or use 'who' command
	cmd := exec.Command("who", "-u")
	output, err := cmd.Output()
	if err == nil && len(output) > 0 {
		scanner := bufio.NewScanner(strings.NewReader(string(output)))
		var users []string
		for scanner.Scan() {
			fields := strings.Fields(scanner.Text())
			if len(fields) >= 1 {
				users = append(users, fields[0])
			}
		}
		if len(users) == 1 {
			return users[0]
		}
		if len(users) > 1 {
			return strings.Join(users, ",")
		}
	}

	// Method 2: Check for recent sudo usage
	// Look at /var/log/auth.log for recent sudo commands

	// Method 3: Fall back to checking environment
	if user := os.Getenv("SUDO_USER"); user != "" {
		return user + " (via sudo)"
	}
	if user := os.Getenv("USER"); user != "" {
		return user
	}

	return "unknown"
}
