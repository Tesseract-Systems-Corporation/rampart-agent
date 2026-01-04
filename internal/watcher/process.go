package watcher

import (
	"bufio"
	"context"
	"log/slog"
	"os"
	"os/exec"
	"path/filepath"
	"regexp"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/Tesseract-Systems-Corporation/rampart-agent/pkg/event"
)

// Default suspicious patterns for process monitoring (CC7.2).
// These patterns detect common attack techniques and suspicious behavior.
var defaultSuspiciousPatterns = []string{
	`curl.*\|.*sh`,             // curl | sh
	`wget.*\|.*sh`,             // wget | sh
	`nc\s+-e`,                  // netcat reverse shell
	`bash\s+-i`,                // interactive bash (potential reverse shell)
	`/tmp/.*\.(sh|py|pl)`,      // scripts in /tmp
	`xmrig|minerd|cryptonight`, // crypto miners
	`base64\s+-d.*\|.*sh`,      // base64 decode to shell
	`python.*-c.*socket`,       // python reverse shell
	`perl.*-e.*socket`,         // perl reverse shell
	`ruby.*-rsocket`,           // ruby reverse shell
	`nc\s+.*-l`,                // netcat listener (nc -l or nc host -l)
	`ncat.*--exec`,             // ncat with exec
	`socat.*exec`,              // socat with exec
}

// ProcessConfig holds configuration for the Process watcher.
type ProcessConfig struct {
	// SuspiciousPatterns contains regex patterns to match suspicious commands.
	// If empty, uses defaultSuspiciousPatterns.
	SuspiciousPatterns []string

	// WatchUsers specifies which users to monitor.
	// If empty, all users are monitored.
	WatchUsers []string

	// PollInterval is how often to poll for new processes.
	// Defaults to 5 seconds if zero.
	PollInterval time.Duration

	// FortressID is the ID of the Fortress this agent belongs to.
	FortressID string

	// ServerID is the ID of this server.
	ServerID string

	// Logger is the logger to use. If nil, uses slog.Default().
	Logger *slog.Logger
}

// ProcessInfo represents a running process.
type ProcessInfo struct {
	PID         int
	PPID        int
	UID         int
	Username    string
	Executable  string
	CommandLine string
	WorkingDir  string
}

// ProcessWatcher monitors process execution for suspicious activity (CC7.2).
type ProcessWatcher struct {
	patterns     []*regexp.Regexp
	watchUsers   map[string]bool
	pollInterval time.Duration
	fortressID   string
	serverID     string
	logger       *slog.Logger
	seenPIDs     map[int]bool
	mu           sync.Mutex
}

// NewProcessWatcher creates a new ProcessWatcher with the given configuration.
func NewProcessWatcher(cfg ProcessConfig) *ProcessWatcher {
	pollInterval := cfg.PollInterval
	if pollInterval == 0 {
		pollInterval = 5 * time.Second
	}

	logger := cfg.Logger
	if logger == nil {
		logger = slog.Default()
	}

	// Compile patterns
	patternStrings := cfg.SuspiciousPatterns
	if len(patternStrings) == 0 {
		patternStrings = defaultSuspiciousPatterns
	}

	patterns := make([]*regexp.Regexp, 0, len(patternStrings))
	for _, p := range patternStrings {
		re, err := regexp.Compile(p)
		if err != nil {
			logger.Warn("invalid pattern", "pattern", p, "error", err)
			continue
		}
		patterns = append(patterns, re)
	}

	// Build watch users map
	watchUsers := make(map[string]bool)
	for _, u := range cfg.WatchUsers {
		watchUsers[u] = true
	}

	return &ProcessWatcher{
		patterns:     patterns,
		watchUsers:   watchUsers,
		pollInterval: pollInterval,
		fortressID:   cfg.FortressID,
		serverID:     cfg.ServerID,
		logger:       logger,
		seenPIDs:     make(map[int]bool),
	}
}

// Watch starts watching for suspicious processes and returns a channel of events.
func (w *ProcessWatcher) Watch(ctx context.Context) (<-chan event.Event, error) {
	out := make(chan event.Event)

	go func() {
		defer close(out)

		w.logger.Info("starting process watcher", "interval", w.pollInterval)

		// Initial scan to populate seen PIDs
		w.scanProcesses(ctx, out, true)

		ticker := time.NewTicker(w.pollInterval)
		defer ticker.Stop()

		for {
			select {
			case <-ctx.Done():
				w.logger.Info("process watcher stopped", "reason", ctx.Err())
				return
			case <-ticker.C:
				w.scanProcesses(ctx, out, false)
			}
		}
	}()

	return out, nil
}

// Name returns the watcher name.
func (w *ProcessWatcher) Name() string {
	return "process"
}

// scanProcesses scans for running processes and emits events for suspicious ones.
func (w *ProcessWatcher) scanProcesses(ctx context.Context, out chan<- event.Event, initialScan bool) {
	processes := w.getProcesses()

	w.mu.Lock()
	defer w.mu.Unlock()

	// Track current PIDs to clean up stale entries
	currentPIDs := make(map[int]bool)

	for _, proc := range processes {
		currentPIDs[proc.PID] = true

		// Skip if already seen
		if w.seenPIDs[proc.PID] {
			continue
		}
		w.seenPIDs[proc.PID] = true

		// Skip if not watching this user (and watchUsers is configured)
		if len(w.watchUsers) > 0 && !w.watchUsers[proc.Username] {
			continue
		}

		// Check if process is suspicious
		reason := w.checkSuspicious(proc)
		if reason == "" {
			continue
		}

		// Don't emit events on initial scan (just populate seen PIDs)
		if initialScan {
			continue
		}

		w.logger.Warn("suspicious process detected",
			"pid", proc.PID,
			"user", proc.Username,
			"command", proc.CommandLine,
			"reason", reason,
		)

		e := createProcessEvent(proc, reason, w.fortressID, w.serverID)
		select {
		case <-ctx.Done():
			return
		case out <- e:
		}
	}

	// Clean up stale PIDs
	for pid := range w.seenPIDs {
		if !currentPIDs[pid] {
			delete(w.seenPIDs, pid)
		}
	}
}

// getProcesses retrieves the list of running processes.
// It tries /proc first (Linux), then falls back to ps command.
func (w *ProcessWatcher) getProcesses() []ProcessInfo {
	// Try /proc filesystem first (Linux)
	processes := w.getProcessesFromProc()
	if len(processes) > 0 {
		return processes
	}

	// Fall back to ps command
	return w.getProcessesFromPS()
}

// getProcessesFromProc reads process information from /proc filesystem.
func (w *ProcessWatcher) getProcessesFromProc() []ProcessInfo {
	var processes []ProcessInfo

	entries, err := os.ReadDir("/proc")
	if err != nil {
		return nil
	}

	for _, entry := range entries {
		if !entry.IsDir() {
			continue
		}

		pid, err := strconv.Atoi(entry.Name())
		if err != nil {
			continue // Not a PID directory
		}

		proc := w.readProcInfo(pid)
		if proc != nil {
			processes = append(processes, *proc)
		}
	}

	return processes
}

// readProcInfo reads process information from /proc/<pid>/.
func (w *ProcessWatcher) readProcInfo(pid int) *ProcessInfo {
	procDir := filepath.Join("/proc", strconv.Itoa(pid))

	// Read cmdline
	cmdlineBytes, err := os.ReadFile(filepath.Join(procDir, "cmdline"))
	if err != nil {
		return nil
	}

	// cmdline is null-separated
	cmdline := strings.ReplaceAll(string(cmdlineBytes), "\x00", " ")
	cmdline = strings.TrimSpace(cmdline)

	if cmdline == "" {
		return nil
	}

	// Read stat for PPID
	statBytes, err := os.ReadFile(filepath.Join(procDir, "stat"))
	if err != nil {
		return nil
	}

	ppid := parsePPIDFromStat(string(statBytes))

	// Read status for UID
	statusBytes, err := os.ReadFile(filepath.Join(procDir, "status"))
	if err != nil {
		return nil
	}

	uid, username := parseUIDFromStatus(string(statusBytes))

	// Read exe symlink for executable path
	exe, _ := os.Readlink(filepath.Join(procDir, "exe"))

	// Read cwd symlink for working directory
	cwd, _ := os.Readlink(filepath.Join(procDir, "cwd"))

	return &ProcessInfo{
		PID:         pid,
		PPID:        ppid,
		UID:         uid,
		Username:    username,
		Executable:  exe,
		CommandLine: cmdline,
		WorkingDir:  cwd,
	}
}

// parsePPIDFromStat parses PPID from /proc/<pid>/stat.
// Format: pid (comm) state ppid ...
func parsePPIDFromStat(stat string) int {
	// Find the closing paren of comm field
	idx := strings.LastIndex(stat, ")")
	if idx < 0 || idx+4 >= len(stat) {
		return 0
	}

	fields := strings.Fields(stat[idx+2:])
	if len(fields) < 2 {
		return 0
	}

	ppid, _ := strconv.Atoi(fields[1])
	return ppid
}

// parseUIDFromStatus parses UID from /proc/<pid>/status.
func parseUIDFromStatus(status string) (int, string) {
	lines := strings.Split(status, "\n")
	uid := 0
	username := ""

	for _, line := range lines {
		if strings.HasPrefix(line, "Uid:") {
			fields := strings.Fields(line)
			if len(fields) >= 2 {
				uid, _ = strconv.Atoi(fields[1])
			}
		}
		if strings.HasPrefix(line, "Name:") {
			fields := strings.Fields(line)
			if len(fields) >= 2 {
				username = fields[1]
			}
		}
	}

	// If we got a UID but no username, try to look it up
	if uid > 0 && username == "" {
		username = lookupUsername(uid)
	}

	return uid, username
}

// lookupUsername looks up a username by UID.
func lookupUsername(uid int) string {
	file, err := os.Open("/etc/passwd")
	if err != nil {
		return ""
	}
	defer file.Close()

	scanner := bufio.NewScanner(file)
	uidStr := strconv.Itoa(uid)

	for scanner.Scan() {
		parts := strings.Split(scanner.Text(), ":")
		if len(parts) >= 3 && parts[2] == uidStr {
			return parts[0]
		}
	}

	return ""
}

// getProcessesFromPS retrieves processes using the ps command.
func (w *ProcessWatcher) getProcessesFromPS() []ProcessInfo {
	var processes []ProcessInfo

	// Use ps with specific format
	output, err := exec.Command("ps", "ax", "-o", "pid,ppid,uid,user,args").Output()
	if err != nil {
		w.logger.Debug("failed to run ps", "error", err)
		return nil
	}

	scanner := bufio.NewScanner(strings.NewReader(string(output)))

	// Skip header
	if scanner.Scan() {
		// First line is header
	}

	for scanner.Scan() {
		proc := parsePSLine(scanner.Text())
		if proc != nil {
			processes = append(processes, *proc)
		}
	}

	return processes
}

// parsePSLine parses a line from ps output.
func parsePSLine(line string) *ProcessInfo {
	line = strings.TrimSpace(line)
	if line == "" {
		return nil
	}

	fields := strings.Fields(line)
	if len(fields) < 5 {
		return nil
	}

	pid, err := strconv.Atoi(fields[0])
	if err != nil {
		return nil
	}

	ppid, _ := strconv.Atoi(fields[1])
	uid, _ := strconv.Atoi(fields[2])
	username := fields[3]

	// Join remaining fields as command line
	cmdline := strings.Join(fields[4:], " ")

	return &ProcessInfo{
		PID:         pid,
		PPID:        ppid,
		UID:         uid,
		Username:    username,
		CommandLine: cmdline,
	}
}

// checkSuspicious checks if a process matches any suspicious patterns.
// Returns the reason if suspicious, empty string otherwise.
func (w *ProcessWatcher) checkSuspicious(proc ProcessInfo) string {
	cmdline := proc.CommandLine

	for _, pattern := range w.patterns {
		if pattern.MatchString(cmdline) {
			return "matched pattern: " + pattern.String()
		}
	}

	return ""
}

// IsSuspiciousCommand checks if a command line matches any suspicious patterns.
// This is exported for testing purposes.
func (w *ProcessWatcher) IsSuspiciousCommand(cmdline string) (bool, string) {
	for _, pattern := range w.patterns {
		if pattern.MatchString(cmdline) {
			return true, pattern.String()
		}
	}
	return false, ""
}

// createProcessEvent creates an event for a suspicious process.
func createProcessEvent(proc ProcessInfo, reason string, fortressID, serverID string) event.Event {
	e := event.NewEvent(event.ProcessSuspicious, fortressID, serverID, map[string]any{
		"pid":              proc.PID,
		"ppid":             proc.PPID,
		"uid":              proc.UID,
		"username":         proc.Username,
		"executable":       proc.Executable,
		"command_line":     proc.CommandLine,
		"working_dir":      proc.WorkingDir,
		"suspicious":       true,
		"suspicion_reason": reason,
	})

	e.Actor = &event.Actor{
		Type: event.ActorTypeUser,
		Name: proc.Username,
	}

	return e
}
