package watcher

import (
	"bufio"
	"context"
	"encoding/json"
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

// DefaultBackupSnapshotInterval is the default interval between backup state checks.
const DefaultBackupSnapshotInterval = 1 * time.Hour

// DefaultMaxBackupAge is the default maximum age before a backup is considered stale.
const DefaultMaxBackupAge = 24 * time.Hour

// BackupProvider represents a detected backup solution.
type BackupProvider string

const (
	BackupProviderRestic    BackupProvider = "restic"
	BackupProviderBorg      BackupProvider = "borg"
	BackupProviderDuplicity BackupProvider = "duplicity"
	BackupProviderRclone    BackupProvider = "rclone"
	BackupProviderAWSBackup BackupProvider = "aws_backup"
	BackupProviderVeeam     BackupProvider = "veeam"
	BackupProviderAcronis   BackupProvider = "acronis"
	BackupProviderRsync     BackupProvider = "rsync"
)

// BackupConfig holds configuration for the Backup watcher.
type BackupConfig struct {
	// SnapshotInterval is how often to check backup state.
	// Defaults to DefaultBackupSnapshotInterval (1 hour) if zero.
	SnapshotInterval time.Duration

	// MaxBackupAge is the maximum age before a backup is considered stale.
	// Defaults to DefaultMaxBackupAge (24 hours) if zero.
	MaxBackupAge time.Duration

	// ResticRepoPath is an optional path to a restic repository.
	// If not set, the watcher will try to detect from environment or common locations.
	ResticRepoPath string

	// BorgRepoPath is an optional path to a borg repository.
	BorgRepoPath string

	// FortressID is the ID of the Fortress this agent belongs to.
	FortressID string

	// ServerID is the ID of this server.
	ServerID string

	// Logger is the logger to use. If nil, uses slog.Default().
	Logger *slog.Logger
}

// BackupWatcher monitors backup solutions and job completion.
type BackupWatcher struct {
	snapshotInterval time.Duration
	maxBackupAge     time.Duration
	resticRepoPath   string
	borgRepoPath     string
	fortressID       string
	serverID         string
	logger           *slog.Logger

	// Track detected providers
	mu                sync.RWMutex
	detectedProviders map[BackupProvider]bool
	lastBackupTimes   map[BackupProvider]time.Time
	lastEmittedStale  map[BackupProvider]time.Time // To avoid spamming stale alerts
}

// NewBackupWatcher creates a new BackupWatcher with the given configuration.
func NewBackupWatcher(cfg BackupConfig) *BackupWatcher {
	interval := cfg.SnapshotInterval
	if interval == 0 {
		interval = DefaultBackupSnapshotInterval
	}

	maxAge := cfg.MaxBackupAge
	if maxAge == 0 {
		maxAge = DefaultMaxBackupAge
	}

	logger := cfg.Logger
	if logger == nil {
		logger = slog.Default()
	}

	return &BackupWatcher{
		snapshotInterval:  interval,
		maxBackupAge:      maxAge,
		resticRepoPath:    cfg.ResticRepoPath,
		borgRepoPath:      cfg.BorgRepoPath,
		fortressID:        cfg.FortressID,
		serverID:          cfg.ServerID,
		logger:            logger,
		detectedProviders: make(map[BackupProvider]bool),
		lastBackupTimes:   make(map[BackupProvider]time.Time),
		lastEmittedStale:  make(map[BackupProvider]time.Time),
	}
}

// Watch starts watching backup state and returns a channel of events.
func (w *BackupWatcher) Watch(ctx context.Context) (<-chan event.Event, error) {
	out := make(chan event.Event)

	go func() {
		defer close(out)

		w.logger.Info("starting backup watcher",
			"interval", w.snapshotInterval,
			"max_backup_age", w.maxBackupAge,
		)

		// Initial detection and snapshot
		w.detectBackupProviders()
		w.emitSnapshot(ctx, out)

		ticker := time.NewTicker(w.snapshotInterval)
		defer ticker.Stop()

		for {
			select {
			case <-ctx.Done():
				w.logger.Info("backup watcher stopped", "reason", ctx.Err())
				return
			case <-ticker.C:
				w.detectBackupProviders()
				w.emitSnapshot(ctx, out)
			}
		}
	}()

	return out, nil
}

// Name returns the watcher name.
func (w *BackupWatcher) Name() string {
	return "backup"
}

// detectBackupProviders detects which backup solutions are installed.
func (w *BackupWatcher) detectBackupProviders() {
	w.mu.Lock()
	defer w.mu.Unlock()

	// Check for restic
	if _, err := exec.LookPath("restic"); err == nil {
		w.detectedProviders[BackupProviderRestic] = true
		w.logger.Debug("detected backup provider", "provider", "restic")
	}

	// Check for borg
	if _, err := exec.LookPath("borg"); err == nil {
		w.detectedProviders[BackupProviderBorg] = true
		w.logger.Debug("detected backup provider", "provider", "borg")
	}

	// Check for duplicity
	if _, err := exec.LookPath("duplicity"); err == nil {
		w.detectedProviders[BackupProviderDuplicity] = true
		w.logger.Debug("detected backup provider", "provider", "duplicity")
	}

	// Check for rclone
	if _, err := exec.LookPath("rclone"); err == nil {
		w.detectedProviders[BackupProviderRclone] = true
		w.logger.Debug("detected backup provider", "provider", "rclone")
	}

	// Check for Veeam agent
	if w.detectVeeam() {
		w.detectedProviders[BackupProviderVeeam] = true
		w.logger.Debug("detected backup provider", "provider", "veeam")
	}

	// Check for Acronis agent
	if w.detectAcronis() {
		w.detectedProviders[BackupProviderAcronis] = true
		w.logger.Debug("detected backup provider", "provider", "acronis")
	}

	// Check for AWS Backup agent
	if w.detectAWSBackup() {
		w.detectedProviders[BackupProviderAWSBackup] = true
		w.logger.Debug("detected backup provider", "provider", "aws_backup")
	}

	// Check for rsync-based backups (via cron)
	if w.detectRsyncBackups() {
		w.detectedProviders[BackupProviderRsync] = true
		w.logger.Debug("detected backup provider", "provider", "rsync")
	}
}

// detectVeeam checks for Veeam backup agent.
func (w *BackupWatcher) detectVeeam() bool {
	// Check for Veeam service
	if output, err := exec.Command("systemctl", "is-active", "veeamservice").Output(); err == nil {
		if strings.TrimSpace(string(output)) == "active" {
			return true
		}
	}

	// Check for Veeam processes
	if output, err := exec.Command("pgrep", "-f", "veeam").Output(); err == nil {
		if len(strings.TrimSpace(string(output))) > 0 {
			return true
		}
	}

	// Check for Veeam binary
	if _, err := exec.LookPath("veeamconfig"); err == nil {
		return true
	}

	return false
}

// detectAcronis checks for Acronis backup agent.
func (w *BackupWatcher) detectAcronis() bool {
	// Check for Acronis service
	if output, err := exec.Command("systemctl", "is-active", "acronis_mms").Output(); err == nil {
		if strings.TrimSpace(string(output)) == "active" {
			return true
		}
	}

	// Check for Acronis processes
	if output, err := exec.Command("pgrep", "-f", "acronis").Output(); err == nil {
		if len(strings.TrimSpace(string(output))) > 0 {
			return true
		}
	}

	return false
}

// detectAWSBackup checks for AWS Backup agent or SSM integration.
func (w *BackupWatcher) detectAWSBackup() bool {
	// Check for AWS Backup vault metadata (indicates EC2 instance with AWS Backup)
	// AWS Backup typically works via AWS APIs, not a local agent
	// But we can check for SSM agent which is often used alongside

	// Check if we're on AWS first
	if !w.isAWSInstance() {
		return false
	}

	// Check for aws-backup related tags or configuration
	// This would require IMDS access which is done in encryption.go
	// For now, just check if SSM agent is present as a proxy
	if output, err := exec.Command("systemctl", "is-active", "amazon-ssm-agent").Output(); err == nil {
		if strings.TrimSpace(string(output)) == "active" {
			return true
		}
	}

	return false
}

// isAWSInstance checks if we're running on AWS.
func (w *BackupWatcher) isAWSInstance() bool {
	// Quick check via IMDS
	cmd := exec.Command("curl", "-s", "--connect-timeout", "1",
		"http://169.254.169.254/latest/meta-data/instance-id")
	output, err := cmd.Output()
	if err != nil {
		return false
	}
	return strings.HasPrefix(string(output), "i-")
}

// detectRsyncBackups checks for rsync-based backup cron jobs.
func (w *BackupWatcher) detectRsyncBackups() bool {
	// Check system crontabs
	cronPaths := []string{
		"/etc/crontab",
		"/etc/cron.d/",
		"/var/spool/cron/crontabs/",
	}

	rsyncPattern := regexp.MustCompile(`rsync\s+.*--backup|rsync\s+.*-a.*backup|backup.*rsync`)

	for _, path := range cronPaths {
		info, err := os.Stat(path)
		if err != nil {
			continue
		}

		if info.IsDir() {
			entries, err := os.ReadDir(path)
			if err != nil {
				continue
			}
			for _, entry := range entries {
				if !entry.IsDir() {
					content, err := os.ReadFile(filepath.Join(path, entry.Name()))
					if err != nil {
						continue
					}
					if rsyncPattern.MatchString(string(content)) {
						return true
					}
				}
			}
		} else {
			content, err := os.ReadFile(path)
			if err != nil {
				continue
			}
			if rsyncPattern.MatchString(string(content)) {
				return true
			}
		}
	}

	// Check systemd timers for rsync-based backups
	if output, err := exec.Command("systemctl", "list-timers", "--all", "--no-pager").Output(); err == nil {
		if strings.Contains(strings.ToLower(string(output)), "rsync") ||
			strings.Contains(strings.ToLower(string(output)), "backup") {
			return true
		}
	}

	return false
}

// emitSnapshot checks backup state and emits events.
func (w *BackupWatcher) emitSnapshot(ctx context.Context, out chan<- event.Event) {
	w.mu.RLock()
	providers := make(map[BackupProvider]bool)
	for k, v := range w.detectedProviders {
		providers[k] = v
	}
	w.mu.RUnlock()

	// Check each detected provider
	for provider := range providers {
		switch provider {
		case BackupProviderRestic:
			w.checkResticBackups(ctx, out)
		case BackupProviderBorg:
			w.checkBorgBackups(ctx, out)
		case BackupProviderDuplicity:
			w.checkDuplicityBackups(ctx, out)
		case BackupProviderRclone:
			w.checkRcloneBackups(ctx, out)
		case BackupProviderVeeam:
			w.checkVeeamBackups(ctx, out)
		case BackupProviderAcronis:
			w.checkAcronisBackups(ctx, out)
		case BackupProviderRsync:
			w.checkRsyncBackups(ctx, out)
		case BackupProviderAWSBackup:
			w.checkAWSBackups(ctx, out)
		}
	}

	// Also check logs for backup events
	w.parseBackupLogs(ctx, out)
}

// ResticSnapshot represents a restic snapshot from JSON output.
type ResticSnapshot struct {
	ID       string    `json:"id"`
	Time     time.Time `json:"time"`
	Hostname string    `json:"hostname"`
	Tags     []string  `json:"tags,omitempty"`
	Paths    []string  `json:"paths"`
	Parent   string    `json:"parent,omitempty"`
}

// checkResticBackups checks restic repository for recent backups.
func (w *BackupWatcher) checkResticBackups(ctx context.Context, out chan<- event.Event) {
	// Determine repository path
	repoPath := w.resticRepoPath
	if repoPath == "" {
		repoPath = os.Getenv("RESTIC_REPOSITORY")
	}

	if repoPath == "" {
		// Try common locations
		commonPaths := []string{
			"/var/backup/restic",
			"/backup/restic",
			"/data/backup/restic",
		}
		for _, path := range commonPaths {
			if _, err := os.Stat(path); err == nil {
				repoPath = path
				break
			}
		}
	}

	if repoPath == "" {
		w.logger.Debug("no restic repository found")
		return
	}

	// Get snapshots
	cmd := exec.CommandContext(ctx, "restic", "-r", repoPath, "snapshots", "--json", "--latest", "1")

	// Pass through environment for credentials
	cmd.Env = os.Environ()

	output, err := cmd.Output()
	if err != nil {
		w.logger.Debug("failed to get restic snapshots", "error", err, "repo", repoPath)
		return
	}

	var snapshots []ResticSnapshot
	if err := json.Unmarshal(output, &snapshots); err != nil {
		w.logger.Debug("failed to parse restic snapshots", "error", err)
		return
	}

	if len(snapshots) == 0 {
		w.logger.Debug("no restic snapshots found", "repo", repoPath)
		return
	}

	// Check the most recent snapshot
	latest := snapshots[0]
	w.mu.Lock()
	w.lastBackupTimes[BackupProviderRestic] = latest.Time
	w.mu.Unlock()

	// Check if backup is stale
	age := time.Since(latest.Time)
	if age > w.maxBackupAge {
		w.emitStaleBackup(ctx, out, BackupProviderRestic, latest.Time, sanitizeRepoPath(repoPath))
	}

	// Emit completion event for recent backup
	if age < w.snapshotInterval*2 {
		w.emitBackupCompleted(ctx, out, BackupProviderRestic, "success", "snapshot",
			0, 0, detectDestination(repoPath), sanitizeRepoPath(repoPath), latest.ID)
	}

	// Check repository integrity
	w.checkResticIntegrity(ctx, out, repoPath)
}

// checkResticIntegrity runs restic check to verify repository integrity.
func (w *BackupWatcher) checkResticIntegrity(ctx context.Context, out chan<- event.Event, repoPath string) {
	// Only run integrity check occasionally (not every snapshot interval)
	// Use a simple time-based approach
	checkFile := filepath.Join(os.TempDir(), "rampart-restic-check-"+sanitizeForFilename(repoPath))
	if info, err := os.Stat(checkFile); err == nil {
		if time.Since(info.ModTime()) < 6*time.Hour {
			return // Skip check if we ran one recently
		}
	}

	cmd := exec.CommandContext(ctx, "restic", "-r", repoPath, "check", "--read-data-subset=1%")
	cmd.Env = os.Environ()

	startTime := time.Now()
	output, err := cmd.CombinedOutput()
	duration := time.Since(startTime)

	// Update check timestamp
	os.WriteFile(checkFile, []byte(time.Now().Format(time.RFC3339)), 0600)

	result := "passed"
	errorCount := 0
	details := ""

	if err != nil {
		result = "failed"
		details = string(output)
		// Count errors in output
		errorCount = strings.Count(strings.ToLower(string(output)), "error")
	}

	payload := map[string]any{
		"provider":            string(BackupProviderRestic),
		"verification_method": "check",
		"result":              result,
		"repository":          sanitizeRepoPath(repoPath),
		"error_count":         errorCount,
		"details":             truncateString(details, 1000),
		"duration_seconds":    int64(duration.Seconds()),
	}

	e := event.NewEvent(event.BackupVerified, w.fortressID, w.serverID, payload)
	select {
	case <-ctx.Done():
		return
	case out <- e:
	}
}

// BorgArchive represents a borg archive from JSON output.
type BorgArchive struct {
	Name  string `json:"name"`
	ID    string `json:"id"`
	Start string `json:"start"`
	End   string `json:"end"`
}

// BorgInfo represents borg info output.
type BorgInfo struct {
	Archives []BorgArchive `json:"archives"`
}

// checkBorgBackups checks borg repository for recent backups.
func (w *BackupWatcher) checkBorgBackups(ctx context.Context, out chan<- event.Event) {
	repoPath := w.borgRepoPath
	if repoPath == "" {
		repoPath = os.Getenv("BORG_REPO")
	}

	if repoPath == "" {
		// Try common locations
		commonPaths := []string{
			"/var/backup/borg",
			"/backup/borg",
			"/data/backup/borg",
		}
		for _, path := range commonPaths {
			if _, err := os.Stat(path); err == nil {
				repoPath = path
				break
			}
		}
	}

	if repoPath == "" {
		w.logger.Debug("no borg repository found")
		return
	}

	// Get archives list
	cmd := exec.CommandContext(ctx, "borg", "info", "--json", repoPath)
	cmd.Env = os.Environ()

	output, err := cmd.Output()
	if err != nil {
		w.logger.Debug("failed to get borg info", "error", err, "repo", repoPath)
		return
	}

	var borgInfo BorgInfo
	if err := json.Unmarshal(output, &borgInfo); err != nil {
		w.logger.Debug("failed to parse borg info", "error", err)
		return
	}

	if len(borgInfo.Archives) == 0 {
		w.logger.Debug("no borg archives found", "repo", repoPath)
		return
	}

	// Get the most recent archive
	latest := borgInfo.Archives[len(borgInfo.Archives)-1]
	latestTime, err := time.Parse(time.RFC3339, latest.End)
	if err != nil {
		latestTime, _ = time.Parse("2006-01-02T15:04:05", latest.End)
	}

	w.mu.Lock()
	w.lastBackupTimes[BackupProviderBorg] = latestTime
	w.mu.Unlock()

	// Check if backup is stale
	age := time.Since(latestTime)
	if age > w.maxBackupAge {
		w.emitStaleBackup(ctx, out, BackupProviderBorg, latestTime, sanitizeRepoPath(repoPath))
	}

	// Emit completion event for recent backup
	if age < w.snapshotInterval*2 {
		w.emitBackupCompleted(ctx, out, BackupProviderBorg, "success", "incremental",
			0, 0, detectDestination(repoPath), sanitizeRepoPath(repoPath), latest.ID)
	}
}

// checkDuplicityBackups checks for duplicity backups.
func (w *BackupWatcher) checkDuplicityBackups(ctx context.Context, out chan<- event.Event) {
	// Duplicity stores status in ~/.cache/duplicity or specified location
	// Check for recent duplicity log entries

	// Parse duplicity logs if available
	logPaths := []string{
		"/var/log/duplicity.log",
		"/var/log/backup/duplicity.log",
	}

	for _, logPath := range logPaths {
		if _, err := os.Stat(logPath); err == nil {
			w.parseDuplicityLog(ctx, out, logPath)
			break
		}
	}

	// Also check systemd journal for duplicity entries
	w.parseJournalForBackup(ctx, out, "duplicity", BackupProviderDuplicity)
}

// parseDuplicityLog parses duplicity log for backup status.
func (w *BackupWatcher) parseDuplicityLog(ctx context.Context, out chan<- event.Event, logPath string) {
	file, err := os.Open(logPath)
	if err != nil {
		return
	}
	defer file.Close()

	// Read last 100 lines
	lines := make([]string, 0, 100)
	scanner := bufio.NewScanner(file)
	for scanner.Scan() {
		lines = append(lines, scanner.Text())
		if len(lines) > 100 {
			lines = lines[1:]
		}
	}

	// Parse for backup completion patterns
	completionPattern := regexp.MustCompile(`(?i)backup statistics|backup completed|errors 0`)
	failurePattern := regexp.MustCompile(`(?i)error|failed|exception`)
	timestampPattern := regexp.MustCompile(`(\d{4}-\d{2}-\d{2}\s+\d{2}:\d{2}:\d{2})`)

	var lastStatus string
	var lastTime time.Time

	for _, line := range lines {
		if matches := timestampPattern.FindStringSubmatch(line); len(matches) > 1 {
			if t, err := time.Parse("2006-01-02 15:04:05", matches[1]); err == nil {
				lastTime = t
			}
		}

		if completionPattern.MatchString(line) {
			lastStatus = "success"
		} else if failurePattern.MatchString(line) && lastStatus != "success" {
			lastStatus = "failed"
		}
	}

	if !lastTime.IsZero() && lastStatus != "" {
		w.mu.Lock()
		w.lastBackupTimes[BackupProviderDuplicity] = lastTime
		w.mu.Unlock()

		age := time.Since(lastTime)
		if age > w.maxBackupAge {
			w.emitStaleBackup(ctx, out, BackupProviderDuplicity, lastTime, "")
		}

		if age < w.snapshotInterval*2 {
			w.emitBackupCompleted(ctx, out, BackupProviderDuplicity, lastStatus, "incremental",
				0, 0, "", "", "")
		}
	}
}

// checkRcloneBackups checks for rclone sync/backup operations.
func (w *BackupWatcher) checkRcloneBackups(ctx context.Context, out chan<- event.Event) {
	// Check rclone logs if available
	logPaths := []string{
		"/var/log/rclone.log",
		"/var/log/backup/rclone.log",
	}

	for _, logPath := range logPaths {
		if _, err := os.Stat(logPath); err == nil {
			w.parseRcloneLog(ctx, out, logPath)
			break
		}
	}

	// Check systemd journal for rclone
	w.parseJournalForBackup(ctx, out, "rclone", BackupProviderRclone)
}

// parseRcloneLog parses rclone log for sync/backup status.
func (w *BackupWatcher) parseRcloneLog(ctx context.Context, out chan<- event.Event, logPath string) {
	file, err := os.Open(logPath)
	if err != nil {
		return
	}
	defer file.Close()

	// Similar pattern to duplicity
	lines := make([]string, 0, 100)
	scanner := bufio.NewScanner(file)
	for scanner.Scan() {
		lines = append(lines, scanner.Text())
		if len(lines) > 100 {
			lines = lines[1:]
		}
	}

	// Parse for completion patterns
	completionPattern := regexp.MustCompile(`(?i)transferred:|copied|synced|checks:\s*\d+`)
	failurePattern := regexp.MustCompile(`(?i)error|failed`)
	timestampPattern := regexp.MustCompile(`(\d{4}/\d{2}/\d{2}\s+\d{2}:\d{2}:\d{2})`)
	sizePattern := regexp.MustCompile(`Transferred:\s+(\d+(?:\.\d+)?)\s*([KMGTP]?i?B)`)

	var lastStatus string
	var lastTime time.Time
	var sizeBytes int64

	for _, line := range lines {
		if matches := timestampPattern.FindStringSubmatch(line); len(matches) > 1 {
			if t, err := time.Parse("2006/01/02 15:04:05", matches[1]); err == nil {
				lastTime = t
			}
		}

		if completionPattern.MatchString(line) {
			lastStatus = "success"
		} else if failurePattern.MatchString(line) && lastStatus != "success" {
			lastStatus = "failed"
		}

		if matches := sizePattern.FindStringSubmatch(line); len(matches) > 2 {
			sizeBytes = parseSize(matches[1], matches[2])
		}
	}

	if !lastTime.IsZero() && lastStatus != "" {
		w.mu.Lock()
		w.lastBackupTimes[BackupProviderRclone] = lastTime
		w.mu.Unlock()

		age := time.Since(lastTime)
		if age > w.maxBackupAge {
			w.emitStaleBackup(ctx, out, BackupProviderRclone, lastTime, "")
		}

		if age < w.snapshotInterval*2 {
			w.emitBackupCompleted(ctx, out, BackupProviderRclone, lastStatus, "sync",
				sizeBytes, 0, "", "", "")
		}
	}
}

// checkVeeamBackups checks Veeam agent backup status.
func (w *BackupWatcher) checkVeeamBackups(ctx context.Context, out chan<- event.Event) {
	// Use veeamconfig to check backup status
	cmd := exec.CommandContext(ctx, "veeamconfig", "session", "list")
	output, err := cmd.Output()
	if err != nil {
		w.logger.Debug("failed to get veeam sessions", "error", err)
		return
	}

	// Parse veeamconfig output for recent sessions
	lines := strings.Split(string(output), "\n")
	timestampPattern := regexp.MustCompile(`(\d{4}-\d{2}-\d{2}\s+\d{2}:\d{2}:\d{2})`)

	var lastTime time.Time
	var lastStatus string

	for _, line := range lines {
		if strings.Contains(strings.ToLower(line), "success") {
			lastStatus = "success"
		} else if strings.Contains(strings.ToLower(line), "failed") {
			lastStatus = "failed"
		}

		if matches := timestampPattern.FindStringSubmatch(line); len(matches) > 1 {
			if t, err := time.Parse("2006-01-02 15:04:05", matches[1]); err == nil {
				if t.After(lastTime) {
					lastTime = t
				}
			}
		}
	}

	if !lastTime.IsZero() {
		w.mu.Lock()
		w.lastBackupTimes[BackupProviderVeeam] = lastTime
		w.mu.Unlock()

		age := time.Since(lastTime)
		if age > w.maxBackupAge {
			w.emitStaleBackup(ctx, out, BackupProviderVeeam, lastTime, "")
		}

		if age < w.snapshotInterval*2 && lastStatus != "" {
			w.emitBackupCompleted(ctx, out, BackupProviderVeeam, lastStatus, "full",
				0, 0, "", "", "")
		}
	}
}

// checkAcronisBackups checks Acronis agent backup status.
func (w *BackupWatcher) checkAcronisBackups(ctx context.Context, out chan<- event.Event) {
	// Acronis typically logs to system journal
	w.parseJournalForBackup(ctx, out, "acronis", BackupProviderAcronis)

	// Also check Acronis-specific log locations
	logPaths := []string{
		"/var/lib/Acronis/BackupAndRecovery/MMS/logs/",
		"/var/log/acronis/",
	}

	for _, logDir := range logPaths {
		if _, err := os.Stat(logDir); err == nil {
			entries, err := os.ReadDir(logDir)
			if err != nil {
				continue
			}

			// Find most recent log file
			var latestLog string
			var latestMod time.Time
			for _, entry := range entries {
				if entry.IsDir() {
					continue
				}
				info, err := entry.Info()
				if err != nil {
					continue
				}
				if info.ModTime().After(latestMod) {
					latestMod = info.ModTime()
					latestLog = filepath.Join(logDir, entry.Name())
				}
			}

			if latestLog != "" {
				w.parseAcronisLog(ctx, out, latestLog)
				break
			}
		}
	}
}

// parseAcronisLog parses Acronis log for backup status.
func (w *BackupWatcher) parseAcronisLog(ctx context.Context, out chan<- event.Event, logPath string) {
	file, err := os.Open(logPath)
	if err != nil {
		return
	}
	defer file.Close()

	// Read last portion of file
	scanner := bufio.NewScanner(file)
	lines := make([]string, 0, 100)
	for scanner.Scan() {
		lines = append(lines, scanner.Text())
		if len(lines) > 100 {
			lines = lines[1:]
		}
	}

	// Look for backup completion patterns
	completionPattern := regexp.MustCompile(`(?i)backup.*completed|task.*finished.*successfully`)
	failurePattern := regexp.MustCompile(`(?i)backup.*failed|error.*backup`)

	var lastStatus string
	for _, line := range lines {
		if completionPattern.MatchString(line) {
			lastStatus = "success"
		} else if failurePattern.MatchString(line) {
			lastStatus = "failed"
		}
	}

	if lastStatus != "" {
		info, _ := os.Stat(logPath)
		if info != nil {
			lastTime := info.ModTime()
			w.mu.Lock()
			w.lastBackupTimes[BackupProviderAcronis] = lastTime
			w.mu.Unlock()

			age := time.Since(lastTime)
			if age > w.maxBackupAge {
				w.emitStaleBackup(ctx, out, BackupProviderAcronis, lastTime, "")
			}

			if age < w.snapshotInterval*2 {
				w.emitBackupCompleted(ctx, out, BackupProviderAcronis, lastStatus, "full",
					0, 0, "", "", "")
			}
		}
	}
}

// checkRsyncBackups checks for rsync-based backup completion in logs.
func (w *BackupWatcher) checkRsyncBackups(ctx context.Context, out chan<- event.Event) {
	// Parse cron logs for rsync backup jobs
	w.parseCronLogs(ctx, out, "rsync", BackupProviderRsync)

	// Check systemd journal
	w.parseJournalForBackup(ctx, out, "rsync", BackupProviderRsync)
}

// checkAWSBackups checks AWS Backup status (limited without API access).
func (w *BackupWatcher) checkAWSBackups(ctx context.Context, out chan<- event.Event) {
	// AWS Backup is managed via AWS console/API
	// We can only detect if the agent/SSM is running
	// Full status would require AWS API calls with credentials

	w.logger.Debug("AWS Backup detected - full status requires AWS API access")

	// We could potentially check SSM agent logs for backup-related commands
	w.parseJournalForBackup(ctx, out, "amazon-ssm-agent", BackupProviderAWSBackup)
}

// parseBackupLogs parses various system logs for backup events.
func (w *BackupWatcher) parseBackupLogs(ctx context.Context, out chan<- event.Event) {
	// Parse /var/log/syslog for backup-related entries
	syslogPaths := []string{
		"/var/log/syslog",
		"/var/log/messages",
	}

	for _, logPath := range syslogPaths {
		if _, err := os.Stat(logPath); err == nil {
			w.parseSyslogForBackups(ctx, out, logPath)
			break
		}
	}

	// Parse cron logs
	cronLogPaths := []string{
		"/var/log/cron",
		"/var/log/cron.log",
	}

	for _, logPath := range cronLogPaths {
		if _, err := os.Stat(logPath); err == nil {
			w.parseCronLogs(ctx, out, "backup", BackupProviderRsync)
			break
		}
	}
}

// parseSyslogForBackups looks for backup-related entries in syslog.
func (w *BackupWatcher) parseSyslogForBackups(ctx context.Context, out chan<- event.Event, logPath string) {
	file, err := os.Open(logPath)
	if err != nil {
		return
	}
	defer file.Close()

	// Read last portion of file (seek to end - 100KB)
	if info, err := file.Stat(); err == nil && info.Size() > 100*1024 {
		file.Seek(-100*1024, 2)
	}

	scanner := bufio.NewScanner(file)
	backupPattern := regexp.MustCompile(`(?i)backup|restic|borg|duplicity|rclone`)
	successPattern := regexp.MustCompile(`(?i)completed|success|finished`)
	failurePattern := regexp.MustCompile(`(?i)failed|error|fatal`)

	for scanner.Scan() {
		line := scanner.Text()
		if !backupPattern.MatchString(line) {
			continue
		}

		// This is a backup-related log line
		// We could emit events here, but need to be careful about duplicates
		// For now, just log for debugging
		if successPattern.MatchString(line) {
			w.logger.Debug("backup success in syslog", "line", truncateString(line, 200))
		} else if failurePattern.MatchString(line) {
			w.logger.Debug("backup failure in syslog", "line", truncateString(line, 200))
		}
	}
}

// parseCronLogs parses cron logs for backup job execution.
func (w *BackupWatcher) parseCronLogs(ctx context.Context, out chan<- event.Event, pattern string, provider BackupProvider) {
	logPath := "/var/log/cron"
	if _, err := os.Stat(logPath); err != nil {
		logPath = "/var/log/cron.log"
		if _, err := os.Stat(logPath); err != nil {
			return
		}
	}

	file, err := os.Open(logPath)
	if err != nil {
		return
	}
	defer file.Close()

	// Read last portion
	if info, err := file.Stat(); err == nil && info.Size() > 50*1024 {
		file.Seek(-50*1024, 2)
	}

	scanner := bufio.NewScanner(file)
	patternRe := regexp.MustCompile(`(?i)` + pattern)

	for scanner.Scan() {
		line := scanner.Text()
		if patternRe.MatchString(line) {
			w.logger.Debug("found backup cron entry", "provider", provider, "line", truncateString(line, 200))
		}
	}
}

// parseJournalForBackup checks systemd journal for backup-related entries.
func (w *BackupWatcher) parseJournalForBackup(ctx context.Context, out chan<- event.Event, unit string, provider BackupProvider) {
	// Get entries from last hour
	cmd := exec.CommandContext(ctx, "journalctl", "-u", unit, "--since", "1 hour ago", "--no-pager", "-q")
	output, err := cmd.Output()
	if err != nil {
		return
	}

	if len(output) == 0 {
		return
	}

	lines := strings.Split(string(output), "\n")
	successPattern := regexp.MustCompile(`(?i)completed|success|finished`)
	failurePattern := regexp.MustCompile(`(?i)failed|error|fatal`)

	var lastStatus string
	for _, line := range lines {
		if successPattern.MatchString(line) {
			lastStatus = "success"
		} else if failurePattern.MatchString(line) {
			lastStatus = "failed"
		}
	}

	if lastStatus != "" {
		w.emitBackupCompleted(ctx, out, provider, lastStatus, "unknown",
			0, 0, "", "", "")
	}
}

// emitBackupCompleted emits a backup.completed event.
func (w *BackupWatcher) emitBackupCompleted(ctx context.Context, out chan<- event.Event,
	provider BackupProvider, status, backupType string,
	sizeBytes, durationSeconds int64,
	destination, repository, snapshotID string) {

	payload := map[string]any{
		"provider":    string(provider),
		"status":      status,
		"backup_type": backupType,
		"destination": destination,
	}

	if sizeBytes > 0 {
		payload["size_bytes"] = sizeBytes
	}
	if durationSeconds > 0 {
		payload["duration_seconds"] = durationSeconds
	}
	if repository != "" {
		payload["repository"] = repository
	}
	if snapshotID != "" {
		payload["snapshot_id"] = snapshotID
	}

	e := event.NewEvent(event.BackupCompleted, w.fortressID, w.serverID, payload)
	select {
	case <-ctx.Done():
		return
	case out <- e:
	}

	w.logger.Info("backup completed",
		"provider", provider,
		"status", status,
		"type", backupType,
	)
}

// emitStaleBackup emits a backup.stale event.
func (w *BackupWatcher) emitStaleBackup(ctx context.Context, out chan<- event.Event,
	provider BackupProvider, lastBackupTime time.Time, repository string) {

	// Avoid spamming stale alerts (only emit once per max_backup_age period)
	w.mu.Lock()
	lastStale, exists := w.lastEmittedStale[provider]
	if exists && time.Since(lastStale) < w.maxBackupAge {
		w.mu.Unlock()
		return
	}
	w.lastEmittedStale[provider] = time.Now()
	w.mu.Unlock()

	hoursSince := int(time.Since(lastBackupTime).Hours())

	payload := map[string]any{
		"provider":             string(provider),
		"last_backup_time":     lastBackupTime.Format(time.RFC3339),
		"hours_since_backup":   hoursSince,
		"max_backup_age_hours": int(w.maxBackupAge.Hours()),
	}

	if repository != "" {
		payload["repository"] = repository
	}

	e := event.NewEvent(event.BackupStale, w.fortressID, w.serverID, payload)
	select {
	case <-ctx.Done():
		return
	case out <- e:
	}

	w.logger.Warn("backup is stale",
		"provider", provider,
		"last_backup", lastBackupTime,
		"hours_since", hoursSince,
	)
}

// Helper functions

// sanitizeRepoPath removes sensitive information from repository paths.
func sanitizeRepoPath(path string) string {
	// Remove credentials from URLs
	// s3:https://key:secret@bucket.s3.amazonaws.com -> s3:https://***@bucket.s3.amazonaws.com
	credentialPattern := regexp.MustCompile(`://([^:]+):([^@]+)@`)
	path = credentialPattern.ReplaceAllString(path, "://***:***@")

	// Remove API keys from query strings
	apiKeyPattern := regexp.MustCompile(`[?&](key|token|password|secret)=[^&]+`)
	path = apiKeyPattern.ReplaceAllString(path, "")

	return path
}

// detectDestination determines the backup destination type from the path.
func detectDestination(path string) string {
	pathLower := strings.ToLower(path)

	if strings.HasPrefix(pathLower, "s3:") || strings.Contains(pathLower, "s3.amazonaws.com") {
		return "s3"
	}
	if strings.HasPrefix(pathLower, "gs:") || strings.Contains(pathLower, "storage.googleapis.com") {
		return "gcs"
	}
	if strings.HasPrefix(pathLower, "azure:") || strings.Contains(pathLower, "blob.core.windows.net") {
		return "azure"
	}
	if strings.HasPrefix(pathLower, "sftp:") || strings.HasPrefix(pathLower, "ssh:") {
		return "sftp"
	}
	if strings.HasPrefix(pathLower, "b2:") {
		return "backblaze"
	}
	if strings.HasPrefix(pathLower, "rest:") || strings.HasPrefix(pathLower, "http") {
		return "rest"
	}
	if strings.HasPrefix(path, "/") {
		return "local"
	}

	return "unknown"
}

// sanitizeForFilename creates a safe filename from a path.
func sanitizeForFilename(path string) string {
	// Replace non-alphanumeric characters with underscores
	re := regexp.MustCompile(`[^a-zA-Z0-9]+`)
	return re.ReplaceAllString(path, "_")
}

// truncateString truncates a string to maxLen characters.
func truncateString(s string, maxLen int) string {
	if len(s) <= maxLen {
		return s
	}
	return s[:maxLen] + "..."
}

// parseSize converts a size string with unit to bytes.
func parseSize(sizeStr, unit string) int64 {
	size, err := strconv.ParseFloat(sizeStr, 64)
	if err != nil {
		return 0
	}

	unitLower := strings.ToLower(unit)
	multiplier := float64(1)

	switch {
	case strings.HasPrefix(unitLower, "k"):
		multiplier = 1024
	case strings.HasPrefix(unitLower, "m"):
		multiplier = 1024 * 1024
	case strings.HasPrefix(unitLower, "g"):
		multiplier = 1024 * 1024 * 1024
	case strings.HasPrefix(unitLower, "t"):
		multiplier = 1024 * 1024 * 1024 * 1024
	case strings.HasPrefix(unitLower, "p"):
		multiplier = 1024 * 1024 * 1024 * 1024 * 1024
	}

	return int64(size * multiplier)
}
