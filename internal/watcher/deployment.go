package watcher

import (
	"context"
	"encoding/json"
	"log/slog"
	"os"
	"path/filepath"
	"strings"
	"time"

	"github.com/Tesseract-Systems-Corporation/rampart-agent/pkg/event"
)

// DeploymentConfig holds configuration for the Deployment watcher.
type DeploymentConfig struct {
	// MarkerDir is the directory where CI/CD pipelines can write deployment
	// marker files. Each file should be a JSON file containing deployment info.
	// Defaults to "/var/run/rampart/deployments" if empty.
	MarkerDir string

	// PollInterval is how often to check for new deployment markers.
	// Defaults to 5 seconds if zero.
	PollInterval time.Duration

	// FortressID is the ID of the Fortress this agent belongs to.
	FortressID string

	// ServerID is the ID of this server.
	ServerID string

	// Logger is the logger to use. If nil, uses slog.Default().
	Logger *slog.Logger
}

// DeploymentWatcher monitors for deployment events from CI/CD pipelines.
// It watches a configurable directory for deployment marker files that
// CI/CD pipelines can create to report deployments.
type DeploymentWatcher struct {
	markerDir    string
	pollInterval time.Duration
	fortressID   string
	serverID     string
	logger       *slog.Logger

	// Track processed files to avoid duplicates
	processed map[string]bool
}

// DeploymentMarker is the expected structure of a deployment marker file.
type DeploymentMarker struct {
	// ID is an optional unique identifier for this deployment
	ID string `json:"id,omitempty"`

	// Type is the deployment event type: "started", "completed", or "failed"
	// Defaults to "completed" if not specified.
	Type string `json:"type,omitempty"`

	// AppName is the name of the application being deployed
	AppName string `json:"app_name"`

	// Version is the version being deployed
	Version string `json:"version,omitempty"`

	// Image is the container image being deployed (if applicable)
	Image string `json:"image,omitempty"`

	// GitCommit is the git commit hash
	GitCommit string `json:"git_commit,omitempty"`

	// GitRepo is the git repository URL
	GitRepo string `json:"git_repo,omitempty"`

	// RollbackOf is set if this deployment is a rollback of a previous version
	RollbackOf string `json:"rollback_of,omitempty"`

	// Pipeline contains CI/CD pipeline information
	Pipeline *PipelineInfo `json:"pipeline,omitempty"`

	// Timestamp is when the deployment occurred (RFC3339 format)
	// Defaults to file modification time if not specified.
	Timestamp string `json:"timestamp,omitempty"`

	// Error is the error message if Type is "failed"
	Error string `json:"error,omitempty"`
}

// PipelineInfo contains information about the CI/CD pipeline.
type PipelineInfo struct {
	Provider  string `json:"provider,omitempty"`   // github, gitlab, jenkins, etc.
	RunID     string `json:"run_id,omitempty"`     // Pipeline run ID
	RunURL    string `json:"run_url,omitempty"`    // URL to the pipeline run
	Initiator string `json:"initiator,omitempty"`  // Who triggered the deployment
	Branch    string `json:"branch,omitempty"`     // Git branch
}

// NewDeploymentWatcher creates a new DeploymentWatcher with the given configuration.
func NewDeploymentWatcher(cfg DeploymentConfig) *DeploymentWatcher {
	markerDir := cfg.MarkerDir
	if markerDir == "" {
		markerDir = "/var/run/rampart/deployments"
	}

	pollInterval := cfg.PollInterval
	if pollInterval == 0 {
		pollInterval = 5 * time.Second
	}

	logger := cfg.Logger
	if logger == nil {
		logger = slog.Default()
	}

	return &DeploymentWatcher{
		markerDir:    markerDir,
		pollInterval: pollInterval,
		fortressID:   cfg.FortressID,
		serverID:     cfg.ServerID,
		logger:       logger,
		processed:    make(map[string]bool),
	}
}

// Watch starts watching for deployment events.
func (w *DeploymentWatcher) Watch(ctx context.Context) (<-chan event.Event, error) {
	out := make(chan event.Event)

	go func() {
		defer close(out)

		// Ensure marker directory exists
		if err := os.MkdirAll(w.markerDir, 0755); err != nil {
			w.logger.Warn("could not create deployment marker directory",
				"path", w.markerDir,
				"error", err,
			)
		}

		w.logger.Info("starting deployment watcher", "marker_dir", w.markerDir)

		// Initial scan of existing files
		w.scanMarkers(ctx, out)

		ticker := time.NewTicker(w.pollInterval)
		defer ticker.Stop()

		for {
			select {
			case <-ctx.Done():
				w.logger.Info("deployment watcher stopped", "reason", ctx.Err())
				return
			case <-ticker.C:
				w.scanMarkers(ctx, out)
			}
		}
	}()

	return out, nil
}

// Name returns the watcher name.
func (w *DeploymentWatcher) Name() string {
	return "deployment"
}

// scanMarkers scans the marker directory for deployment files.
func (w *DeploymentWatcher) scanMarkers(ctx context.Context, out chan<- event.Event) {
	entries, err := os.ReadDir(w.markerDir)
	if err != nil {
		if !os.IsNotExist(err) {
			w.logger.Debug("could not read deployment marker directory",
				"path", w.markerDir,
				"error", err,
			)
		}
		return
	}

	for _, entry := range entries {
		if entry.IsDir() {
			continue
		}

		// Only process JSON files
		name := entry.Name()
		if !strings.HasSuffix(name, ".json") {
			continue
		}

		// Skip already processed files
		if w.processed[name] {
			continue
		}

		filePath := filepath.Join(w.markerDir, name)
		e := w.processMarkerFile(filePath)
		if e != nil {
			select {
			case <-ctx.Done():
				return
			case out <- *e:
			}
		}

		// Mark as processed
		w.processed[name] = true

		// Remove the marker file after processing
		if err := os.Remove(filePath); err != nil {
			w.logger.Warn("could not remove processed marker file",
				"path", filePath,
				"error", err,
			)
		}
	}
}

// processMarkerFile reads and processes a deployment marker file.
func (w *DeploymentWatcher) processMarkerFile(filePath string) *event.Event {
	data, err := os.ReadFile(filePath)
	if err != nil {
		w.logger.Warn("could not read deployment marker file",
			"path", filePath,
			"error", err,
		)
		return nil
	}

	var marker DeploymentMarker
	if err := json.Unmarshal(data, &marker); err != nil {
		w.logger.Warn("could not parse deployment marker file",
			"path", filePath,
			"error", err,
		)
		return nil
	}

	// Validate required fields
	if marker.AppName == "" {
		w.logger.Warn("deployment marker missing app_name",
			"path", filePath,
		)
		return nil
	}

	// Determine event type
	var eventType event.EventType
	switch strings.ToLower(marker.Type) {
	case "started":
		eventType = event.DeploymentStarted
	case "failed":
		eventType = event.DeploymentFailed
	default:
		eventType = event.DeploymentCompleted
	}

	// Build payload
	payload := map[string]any{
		"app_name": marker.AppName,
	}

	if marker.Version != "" {
		payload["version"] = marker.Version
	}
	if marker.Image != "" {
		payload["image"] = marker.Image
	}
	if marker.GitCommit != "" {
		payload["git_commit"] = marker.GitCommit
	}
	if marker.GitRepo != "" {
		payload["git_repo"] = marker.GitRepo
	}
	if marker.RollbackOf != "" {
		payload["rollback_of"] = marker.RollbackOf
	}
	if marker.Error != "" {
		payload["error"] = marker.Error
	}

	// Add pipeline info if present
	if marker.Pipeline != nil {
		if marker.Pipeline.Provider != "" {
			payload["pipeline_provider"] = marker.Pipeline.Provider
		}
		if marker.Pipeline.RunID != "" {
			payload["pipeline_run_id"] = marker.Pipeline.RunID
		}
		if marker.Pipeline.RunURL != "" {
			payload["pipeline_run_url"] = marker.Pipeline.RunURL
		}
		if marker.Pipeline.Initiator != "" {
			payload["initiated_by"] = marker.Pipeline.Initiator
		}
		if marker.Pipeline.Branch != "" {
			payload["git_branch"] = marker.Pipeline.Branch
		}
	}

	e := event.NewEvent(eventType, w.fortressID, w.serverID, payload)

	// Set timestamp from marker if provided
	if marker.Timestamp != "" {
		if ts, err := time.Parse(time.RFC3339, marker.Timestamp); err == nil {
			e.Timestamp = ts
		}
	}

	// Set actor based on pipeline info
	if marker.Pipeline != nil && marker.Pipeline.Provider != "" {
		e.Actor = &event.Actor{
			Type: event.ActorTypeService,
			Name: marker.Pipeline.Provider,
		}
		if marker.Pipeline.Initiator != "" {
			e.Actor.ID = marker.Pipeline.Initiator
		}
	} else {
		e.Actor = &event.Actor{
			Type: event.ActorTypeSystem,
			Name: "ci-cd",
		}
	}

	w.logger.Info("deployment event detected",
		"type", eventType,
		"app", marker.AppName,
		"version", marker.Version,
	)

	return &e
}
