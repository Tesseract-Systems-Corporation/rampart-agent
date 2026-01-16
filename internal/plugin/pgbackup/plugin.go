// Package pgbackup provides a plugin for PostgreSQL database backups.
package pgbackup

import (
	"context"
	_ "embed"
	"encoding/json"
	"log/slog"
	"sync"

	"github.com/Tesseract-Systems-Corporation/rampart-agent/internal/backup"
	"github.com/Tesseract-Systems-Corporation/rampart-agent/internal/plugin"
	"github.com/Tesseract-Systems-Corporation/rampart-agent/pkg/event"
)

//go:embed manifest.yaml
var manifestData []byte

var (
	manifestOnce   sync.Once
	parsedManifest *plugin.Manifest
	manifestErr    error
)

// GetManifest returns the parsed plugin manifest.
// The manifest is parsed once and cached.
func GetManifest() (*plugin.Manifest, error) {
	manifestOnce.Do(func() {
		parsedManifest, manifestErr = plugin.ParseManifest(manifestData)
	})
	return parsedManifest, manifestErr
}

// Plugin handles PostgreSQL backup commands.
type Plugin struct {
	executor   *backup.PGExecutor
	logger     *slog.Logger
	fortressID string
	serverID   string
	manifest   *plugin.Manifest
}

// New creates a new PostgreSQL backup plugin.
func New(logger *slog.Logger, fortressID, serverID string) *Plugin {
	manifest, err := GetManifest()
	if err != nil {
		logger.Error("failed to parse pg_backup manifest", "error", err)
	}

	return &Plugin{
		executor:   backup.NewPGExecutor(logger),
		logger:     logger.With("plugin", "pg_backup"),
		fortressID: fortressID,
		serverID:   serverID,
		manifest:   manifest,
	}
}

func (p *Plugin) Name() string    { return "pg_backup" }
func (p *Plugin) Version() string { return "1.0.0" }

// Manifest returns the plugin's manifest.
func (p *Plugin) Manifest() *plugin.Manifest {
	return p.manifest
}

func (p *Plugin) Commands() []string {
	if p.manifest != nil {
		return p.manifest.CommandNames()
	}
	return []string{"trigger_pg_backup", "test_pg_connection"}
}

func (p *Plugin) Execute(ctx context.Context, cmd plugin.Command, emit plugin.Emitter) error {
	switch cmd.Type {
	case "trigger_pg_backup":
		return p.handleBackup(ctx, cmd, emit)
	case "test_pg_connection":
		return p.handleTestConnection(ctx, cmd, emit)
	default:
		return nil
	}
}

// backupPayload is the expected payload for trigger_pg_backup command.
type backupPayload struct {
	JobID              string `json:"job_id"`
	DatasourceID       string `json:"datasource_id"`
	Host               string `json:"host"`
	Port               int    `json:"port"`
	Database           string `json:"database"`
	Username           string `json:"username"`
	Password           string `json:"password"`
	SSLMode            string `json:"ssl_mode"`
	BackupAllDatabases bool   `json:"backup_all_databases"`
	StorageType        string `json:"storage_type"`
	StoragePath        string `json:"storage_path"`
	S3Endpoint         string `json:"s3_endpoint"`
	S3AccessKey        string `json:"s3_access_key"`
	S3SecretKey        string `json:"s3_secret_key"`
	S3Region           string `json:"s3_region"`
}

func (p *Plugin) handleBackup(ctx context.Context, cmd plugin.Command, emit plugin.Emitter) error {
	var payload backupPayload
	if err := json.Unmarshal(cmd.Payload, &payload); err != nil {
		p.logger.Error("failed to parse pg_backup payload", "error", err)
		return err
	}

	p.logger.Info("starting pg backup",
		"job_id", payload.JobID,
		"database", payload.Database,
		"host", payload.Host,
	)

	cfg := backup.BackupConfig{
		JobID:              payload.JobID,
		DatasourceID:       payload.DatasourceID,
		Host:               payload.Host,
		Port:               payload.Port,
		Database:           payload.Database,
		Username:           payload.Username,
		Password:           payload.Password,
		SSLMode:            payload.SSLMode,
		BackupAllDatabases: payload.BackupAllDatabases,
		StorageType:        payload.StorageType,
		StoragePath:        payload.StoragePath,
		S3Endpoint:         payload.S3Endpoint,
		S3AccessKey:        payload.S3AccessKey,
		S3SecretKey:        payload.S3SecretKey,
		S3Region:           payload.S3Region,
	}

	// Create a progress channel
	progressCh := make(chan backup.BackupProgress, 100)

	// Start the backup in a goroutine
	go p.executor.Execute(ctx, cfg, progressCh)

	// Forward progress updates as events (send immediately for real-time updates)
	for progress := range progressCh {
		ev := event.NewEvent(event.PGBackupProgress, "", "", map[string]any{
			"job_id":           progress.JobID,
			"datasource_id":    progress.DatasourceID,
			"status":           progress.Status,
			"progress_percent": progress.ProgressPercent,
			"current_phase":    progress.CurrentPhase,
			"size_bytes":       progress.SizeBytes,
			"duration_seconds": progress.DurationSeconds,
			"backup_path":      progress.BackupPath,
			"error_message":    progress.ErrorMessage,
		})
		if err := emit.SendImmediate(ctx, ev); err != nil {
			p.logger.Warn("failed to send backup progress event", "error", err)
		}
	}

	return nil
}

// testConnectionPayload is the expected payload for test_pg_connection command.
type testConnectionPayload struct {
	CommandID    string `json:"command_id"`
	DatasourceID string `json:"datasource_id"`
	Host         string `json:"host"`
	Port         int    `json:"port"`
	Database     string `json:"database"`
	Username     string `json:"username"`
	Password     string `json:"password"`
	SSLMode      string `json:"ssl_mode"`
}

func (p *Plugin) handleTestConnection(ctx context.Context, cmd plugin.Command, emit plugin.Emitter) error {
	var payload testConnectionPayload
	if err := json.Unmarshal(cmd.Payload, &payload); err != nil {
		p.logger.Error("failed to parse test_pg_connection payload", "error", err)
		return err
	}

	p.logger.Info("testing pg connection",
		"datasource_id", payload.DatasourceID,
		"host", payload.Host,
		"database", payload.Database,
	)

	cfg := backup.BackupConfig{
		DatasourceID: payload.DatasourceID,
		Host:         payload.Host,
		Port:         payload.Port,
		Database:     payload.Database,
		Username:     payload.Username,
		Password:     payload.Password,
		SSLMode:      payload.SSLMode,
	}

	success, err := p.executor.TestConnection(ctx, cfg)

	result := map[string]any{
		"command_id":    payload.CommandID,
		"datasource_id": payload.DatasourceID,
		"success":       success,
	}
	if err != nil {
		result["error"] = err.Error()
	}

	ev := event.NewEvent(event.PGConnectionTestResult, p.fortressID, p.serverID, result)
	// Send immediately - command responses need instant delivery
	if sendErr := emit.SendImmediate(ctx, ev); sendErr != nil {
		p.logger.Error("failed to send test result", "error", sendErr)
		return sendErr
	}

	return nil
}
