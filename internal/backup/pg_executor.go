// Package backup provides database backup execution for the agent.
package backup

import (
	"bufio"
	"compress/gzip"
	"context"
	"database/sql"
	"fmt"
	"log/slog"
	"os"
	"os/exec"
	"path/filepath"
	"regexp"
	"strconv"
	"strings"
	"time"

	_ "github.com/lib/pq" // PostgreSQL driver
)

// BackupConfig contains configuration for a backup job.
type BackupConfig struct {
	JobID        string
	DatasourceID string
	Host         string
	Port         int
	Database     string
	Username     string
	Password     string
	SSLMode      string
	StorageType  string // "local" or "s3"
	StoragePath  string
}

// BackupProgress represents the progress of a backup job.
type BackupProgress struct {
	JobID           string `json:"job_id"`
	DatasourceID    string `json:"datasource_id"`
	Status          string `json:"status"`
	ProgressPercent int    `json:"progress_percent"`
	CurrentPhase    string `json:"current_phase"`
	SizeBytes       int64  `json:"size_bytes,omitempty"`
	DurationSeconds int64  `json:"duration_seconds,omitempty"`
	BackupPath      string `json:"backup_path,omitempty"`
	ErrorMessage    string `json:"error_message,omitempty"`
}

// PGExecutor executes PostgreSQL backup jobs.
type PGExecutor struct {
	logger *slog.Logger
}

// NewPGExecutor creates a new PostgreSQL backup executor.
func NewPGExecutor(logger *slog.Logger) *PGExecutor {
	return &PGExecutor{
		logger: logger.With("component", "pg-executor"),
	}
}

// Execute runs a PostgreSQL backup and reports progress.
func (e *PGExecutor) Execute(ctx context.Context, cfg BackupConfig, progressCh chan<- BackupProgress) {
	startTime := time.Now()

	// Helper to send progress
	sendProgress := func(status string, percent int, phase string, err error) {
		progress := BackupProgress{
			JobID:           cfg.JobID,
			DatasourceID:    cfg.DatasourceID,
			Status:          status,
			ProgressPercent: percent,
			CurrentPhase:    phase,
			DurationSeconds: int64(time.Since(startTime).Seconds()),
		}
		if err != nil {
			progress.ErrorMessage = err.Error()
		}
		select {
		case progressCh <- progress:
		default:
			e.logger.Warn("progress channel full, dropping update")
		}
	}

	e.logger.Info("starting backup",
		"job_id", cfg.JobID,
		"database", cfg.Database,
		"host", cfg.Host,
	)

	// Phase 1: Connecting
	sendProgress("running", 5, "connecting", nil)

	// Test connection first
	connStr := fmt.Sprintf("host=%s port=%d user=%s password=%s dbname=%s sslmode=%s",
		cfg.Host, cfg.Port, cfg.Username, cfg.Password, cfg.Database, cfg.SSLMode)

	db, err := sql.Open("postgres", connStr)
	if err != nil {
		sendProgress("failed", 5, "connecting", fmt.Errorf("failed to create connection: %w", err))
		return
	}
	defer db.Close()

	// Set connection timeout
	db.SetConnMaxIdleTime(5 * time.Second)

	ctx, cancel := context.WithTimeout(ctx, 30*time.Second)
	defer cancel()

	if err := db.PingContext(ctx); err != nil {
		sendProgress("failed", 5, "connecting", fmt.Errorf("failed to connect: %w", err))
		return
	}

	// Get database size for progress estimation
	var dbSize int64
	err = db.QueryRowContext(ctx, "SELECT pg_database_size($1)", cfg.Database).Scan(&dbSize)
	if err != nil {
		e.logger.Warn("could not get database size", "error", err)
		dbSize = 0
	}

	sendProgress("running", 10, "dumping", nil)

	// Phase 2: Create backup directory
	backupDir := cfg.StoragePath
	if backupDir == "" {
		backupDir = "/var/lib/rampart/backups"
	}

	if err := os.MkdirAll(backupDir, 0755); err != nil {
		sendProgress("failed", 10, "dumping", fmt.Errorf("failed to create backup directory: %w", err))
		return
	}

	// Generate backup filename
	timestamp := time.Now().Format("20060102-150405")
	backupFile := filepath.Join(backupDir, fmt.Sprintf("%s_%s.sql.gz", cfg.Database, timestamp))

	// Phase 3: Run pg_dump
	sendProgress("running", 15, "dumping", nil)

	// Set PGPASSWORD environment variable
	env := append(os.Environ(), fmt.Sprintf("PGPASSWORD=%s", cfg.Password))

	// Build pg_dump command
	args := []string{
		"-h", cfg.Host,
		"-p", strconv.Itoa(cfg.Port),
		"-U", cfg.Username,
		"-d", cfg.Database,
		"-v", // verbose for progress tracking
		"-F", "p", // plain text format (for compression)
	}

	cmd := exec.CommandContext(ctx, "pg_dump", args...)
	cmd.Env = env

	// Create output file with gzip compression
	outFile, err := os.Create(backupFile)
	if err != nil {
		sendProgress("failed", 15, "dumping", fmt.Errorf("failed to create backup file: %w", err))
		return
	}
	defer outFile.Close()

	gzWriter := gzip.NewWriter(outFile)
	defer gzWriter.Close()

	// Capture stdout for the dump
	stdout, err := cmd.StdoutPipe()
	if err != nil {
		sendProgress("failed", 15, "dumping", fmt.Errorf("failed to create stdout pipe: %w", err))
		return
	}

	// Capture stderr for progress messages
	stderr, err := cmd.StderrPipe()
	if err != nil {
		sendProgress("failed", 15, "dumping", fmt.Errorf("failed to create stderr pipe: %w", err))
		return
	}

	if err := cmd.Start(); err != nil {
		sendProgress("failed", 15, "dumping", fmt.Errorf("failed to start pg_dump: %w", err))
		return
	}

	// Track bytes written for progress
	var bytesWritten int64
	progressTicker := time.NewTicker(2 * time.Second)
	defer progressTicker.Stop()

	// Copy stdout to gzip file and track progress
	go func() {
		buf := make([]byte, 32*1024) // 32KB buffer
		for {
			n, err := stdout.Read(buf)
			if n > 0 {
				gzWriter.Write(buf[:n])
				bytesWritten += int64(n)
			}
			if err != nil {
				break
			}
		}
	}()

	// Parse stderr for progress (pg_dump verbose output)
	go func() {
		scanner := bufio.NewScanner(stderr)
		tableRegex := regexp.MustCompile(`dumping contents of table "(.+)"`)
		for scanner.Scan() {
			line := scanner.Text()
			if matches := tableRegex.FindStringSubmatch(line); len(matches) > 1 {
				e.logger.Debug("dumping table", "table", matches[1])
			}
		}
	}()

	// Send progress updates while dumping
	done := make(chan error, 1)
	go func() {
		done <- cmd.Wait()
	}()

	dumpLoop:
	for {
		select {
		case <-ctx.Done():
			cmd.Process.Kill()
			sendProgress("failed", 50, "dumping", ctx.Err())
			return
		case err := <-done:
			if err != nil {
				sendProgress("failed", 50, "dumping", fmt.Errorf("pg_dump failed: %w", err))
				os.Remove(backupFile)
				return
			}
			break dumpLoop
		case <-progressTicker.C:
			// Estimate progress based on bytes written vs database size
			percent := 15
			if dbSize > 0 {
				// Estimate: raw dump is roughly 50% of DB size after compression
				estimatedTotal := dbSize / 2
				percent = 15 + int(float64(bytesWritten)/float64(estimatedTotal)*70)
				if percent > 85 {
					percent = 85
				}
			}
			sendProgress("running", percent, "dumping", nil)
		}
	}

	// Close gzip writer to flush
	gzWriter.Close()
	outFile.Close()

	// Phase 4: Finalize
	sendProgress("running", 90, "finalizing", nil)

	// Get final file size
	fileInfo, err := os.Stat(backupFile)
	if err != nil {
		e.logger.Warn("could not stat backup file", "error", err)
	}

	var finalSize int64
	if fileInfo != nil {
		finalSize = fileInfo.Size()
	}

	// Phase 5: Complete
	duration := time.Since(startTime)
	progress := BackupProgress{
		JobID:           cfg.JobID,
		DatasourceID:    cfg.DatasourceID,
		Status:          "completed",
		ProgressPercent: 100,
		CurrentPhase:    "completed",
		SizeBytes:       finalSize,
		DurationSeconds: int64(duration.Seconds()),
		BackupPath:      backupFile,
	}
	progressCh <- progress

	e.logger.Info("backup completed",
		"job_id", cfg.JobID,
		"database", cfg.Database,
		"size_bytes", finalSize,
		"duration", duration,
		"path", backupFile,
	)
}

// TestConnection tests a PostgreSQL connection.
func (e *PGExecutor) TestConnection(ctx context.Context, cfg BackupConfig) (bool, error) {
	connStr := fmt.Sprintf("host=%s port=%d user=%s password=%s dbname=%s sslmode=%s",
		cfg.Host, cfg.Port, cfg.Username, cfg.Password, cfg.Database, cfg.SSLMode)

	db, err := sql.Open("postgres", connStr)
	if err != nil {
		return false, fmt.Errorf("failed to create connection: %w", err)
	}
	defer db.Close()

	db.SetConnMaxIdleTime(5 * time.Second)

	ctx, cancel := context.WithTimeout(ctx, 10*time.Second)
	defer cancel()

	if err := db.PingContext(ctx); err != nil {
		return false, fmt.Errorf("connection test failed: %w", err)
	}

	// Try a simple query
	var version string
	if err := db.QueryRowContext(ctx, "SELECT version()").Scan(&version); err != nil {
		return false, fmt.Errorf("version query failed: %w", err)
	}

	e.logger.Info("connection test successful",
		"host", cfg.Host,
		"database", cfg.Database,
		"version", strings.Split(version, " ")[0:2],
	)

	return true, nil
}
