package watcher

import (
	"bufio"
	"context"
	"log/slog"
	"regexp"
	"strings"
	"sync"
	"time"

	"github.com/docker/docker/api/types/container"
	"github.com/docker/docker/client"
	"github.com/Tesseract-Systems-Corporation/rampart-agent/pkg/event"
)

// LogsConfig holds configuration for the Logs watcher.
type LogsConfig struct {
	// ScanInterval is how often to report error rates.
	// Defaults to 1 minute if zero.
	ScanInterval time.Duration

	// SocketPath is the path to the Docker socket.
	SocketPath string

	// FortressID is the ID of the Fortress this agent belongs to.
	FortressID string

	// ServerID is the ID of this server.
	ServerID string

	// Logger is the logger to use. If nil, uses slog.Default().
	Logger *slog.Logger
}

// LogsWatcher monitors container logs for errors.
type LogsWatcher struct {
	scanInterval time.Duration
	socketPath   string
	fortressID   string
	serverID     string
	logger       *slog.Logger

	// Track error counts per container
	errorCounts map[string]*containerErrorStats
	mu          sync.Mutex
}

type containerErrorStats struct {
	containerName string
	image         string
	errorCount    int
	warnCount     int
	lastError     string
	lastSeen      time.Time
}

// Error patterns to match in logs
var errorPatterns = []*regexp.Regexp{
	regexp.MustCompile(`(?i)\b(error|err|fatal|panic|exception|failed|failure)\b`),
	regexp.MustCompile(`(?i)\b(critical|crit)\b`),
	regexp.MustCompile(`(?i)stack\s*trace`),
	regexp.MustCompile(`(?i)unhandled\s+exception`),
}

var warnPatterns = []*regexp.Regexp{
	regexp.MustCompile(`(?i)\b(warn|warning)\b`),
	regexp.MustCompile(`(?i)\b(deprecated)\b`),
}

// NewLogsWatcher creates a new LogsWatcher with the given configuration.
func NewLogsWatcher(cfg LogsConfig) *LogsWatcher {
	scanInterval := cfg.ScanInterval
	if scanInterval == 0 {
		scanInterval = time.Minute
	}

	socketPath := cfg.SocketPath
	if socketPath == "" {
		socketPath = "/var/run/docker.sock"
	}

	logger := cfg.Logger
	if logger == nil {
		logger = slog.Default()
	}

	return &LogsWatcher{
		scanInterval: scanInterval,
		socketPath:   socketPath,
		fortressID:   cfg.FortressID,
		serverID:     cfg.ServerID,
		logger:       logger,
		errorCounts:  make(map[string]*containerErrorStats),
	}
}

// Watch starts watching container logs and returns a channel of events.
func (w *LogsWatcher) Watch(ctx context.Context) (<-chan event.Event, error) {
	cli, err := client.NewClientWithOpts(
		client.WithHost("unix://"+w.socketPath),
		client.WithAPIVersionNegotiation(),
	)
	if err != nil {
		return nil, err
	}

	out := make(chan event.Event)

	go func() {
		defer close(out)
		defer cli.Close()

		w.logger.Info("starting logs watcher", "interval", w.scanInterval)

		// Start watching logs for all running containers
		w.startLogWatchers(ctx, cli)

		// Periodically report error rates
		ticker := time.NewTicker(w.scanInterval)
		defer ticker.Stop()

		for {
			select {
			case <-ctx.Done():
				w.logger.Info("logs watcher stopped", "reason", ctx.Err())
				return
			case <-ticker.C:
				w.reportErrorRates(ctx, out)
			}
		}
	}()

	return out, nil
}

// Name returns the watcher name.
func (w *LogsWatcher) Name() string {
	return "logs"
}

// startLogWatchers starts log watchers for all running containers.
func (w *LogsWatcher) startLogWatchers(ctx context.Context, cli *client.Client) {
	containers, err := cli.ContainerList(ctx, container.ListOptions{})
	if err != nil {
		w.logger.Error("failed to list containers", "error", err)
		return
	}

	for _, c := range containers {
		go w.watchContainerLogs(ctx, cli, c.ID, c.Names[0], c.Image)
	}
}

// watchContainerLogs watches logs for a single container.
func (w *LogsWatcher) watchContainerLogs(ctx context.Context, cli *client.Client, containerID, containerName, image string) {
	// Clean up container name (remove leading /)
	containerName = strings.TrimPrefix(containerName, "/")

	// Skip monitoring the agent's own container to avoid feedback loops
	if containerName == "rampart-agent" || strings.HasPrefix(image, "rampart-agent") {
		w.logger.Debug("skipping self-monitoring", "container", containerName)
		return
	}

	// Initialize stats
	w.mu.Lock()
	w.errorCounts[containerID] = &containerErrorStats{
		containerName: containerName,
		image:         image,
	}
	w.mu.Unlock()

	// Get logs from now onwards
	options := container.LogsOptions{
		ShowStdout: true,
		ShowStderr: true,
		Follow:     true,
		Since:      "0s",
		Tail:       "0", // Don't get historical logs
	}

	logs, err := cli.ContainerLogs(ctx, containerID, options)
	if err != nil {
		w.logger.Debug("failed to get container logs", "container", containerName, "error", err)
		return
	}
	defer logs.Close()

	scanner := bufio.NewScanner(logs)
	// Docker logs have an 8-byte header, skip it by reading larger chunks
	buf := make([]byte, 64*1024)
	scanner.Buffer(buf, 64*1024)

	for scanner.Scan() {
		select {
		case <-ctx.Done():
			return
		default:
		}

		line := scanner.Text()
		// Skip the 8-byte docker log header if present
		if len(line) > 8 {
			line = line[8:]
		}

		w.processLogLine(containerID, line)
	}
}

// processLogLine checks a log line for errors/warnings and updates stats.
func (w *LogsWatcher) processLogLine(containerID, line string) {
	w.mu.Lock()
	defer w.mu.Unlock()

	stats, ok := w.errorCounts[containerID]
	if !ok {
		return
	}

	// Check for errors
	for _, pattern := range errorPatterns {
		if pattern.MatchString(line) {
			stats.errorCount++
			stats.lastError = truncate(line, 200)
			stats.lastSeen = time.Now()
			return
		}
	}

	// Check for warnings
	for _, pattern := range warnPatterns {
		if pattern.MatchString(line) {
			stats.warnCount++
			stats.lastSeen = time.Now()
			return
		}
	}
}

// reportErrorRates emits events for containers with errors.
func (w *LogsWatcher) reportErrorRates(ctx context.Context, out chan<- event.Event) {
	w.mu.Lock()
	defer w.mu.Unlock()

	for containerID, stats := range w.errorCounts {
		// Only report if there are errors or warnings
		if stats.errorCount == 0 && stats.warnCount == 0 {
			continue
		}

		// Emit health event with error rates
		e := event.NewEvent(event.HealthDegraded, w.fortressID, w.serverID, map[string]any{
			"container_id":   containerID,
			"container_name": stats.containerName,
			"image":          stats.image,
			"error_count":    stats.errorCount,
			"warn_count":     stats.warnCount,
			"last_error":     stats.lastError,
			"period_seconds": int(w.scanInterval.Seconds()),
			"description":    "Container error rate detected",
		})

		w.logger.Info("container errors detected",
			"container", stats.containerName,
			"errors", stats.errorCount,
			"warnings", stats.warnCount,
		)

		select {
		case <-ctx.Done():
			return
		case out <- e:
		}

		// Reset counts for next period
		stats.errorCount = 0
		stats.warnCount = 0
	}
}

func truncate(s string, maxLen int) string {
	if len(s) <= maxLen {
		return s
	}
	return s[:maxLen] + "..."
}
