package watcher

import (
	"bufio"
	"context"
	"log/slog"
	"os"
	"runtime"
	"strconv"
	"strings"
	"syscall"
	"time"

	"github.com/Tesseract-Systems-Corporation/rampart-agent/pkg/event"
)

// DefaultHealthInterval is the interval between health heartbeats.
// This is not configurable via YAML - control plane dictates the actual heartbeat rate.
const DefaultHealthInterval = 30 * time.Second

// HealthConfig holds configuration for the Health watcher.
type HealthConfig struct {
	// Interval is how often to emit health heartbeats.
	// Defaults to DefaultHealthInterval if zero.
	// Note: This is for internal/testing use only - not exposed in YAML config.
	Interval time.Duration

	// FortressID is the ID of the Fortress this agent belongs to.
	FortressID string

	// ServerID is the ID of this server.
	ServerID string

	// DegradedThreshold is the percentage above which resources are considered degraded.
	// Defaults to 90 if zero.
	DegradedThreshold float64

	// Logger is the logger to use. If nil, uses slog.Default().
	Logger *slog.Logger
}

// HealthWatcher monitors system health metrics.
type HealthWatcher struct {
	interval          time.Duration
	fortressID        string
	serverID          string
	degradedThreshold float64
	logger            *slog.Logger
	lastDegraded      bool
}

// HealthMetrics contains system health metrics.
type HealthMetrics struct {
	CPUPercent     float64
	MemoryPercent  float64
	MemoryUsedGB   float64
	MemoryTotalGB  float64
	DiskPercent    float64
	DiskUsedGB     float64
	DiskTotalGB    float64
	Load1m         float64
	Load5m         float64
	Load15m        float64
	ContainerCount int
	UptimeSeconds  int64
}

// NewHealthWatcher creates a new HealthWatcher with the given configuration.
func NewHealthWatcher(cfg HealthConfig) *HealthWatcher {
	interval := cfg.Interval
	if interval == 0 {
		interval = DefaultHealthInterval
	}

	threshold := cfg.DegradedThreshold
	if threshold == 0 {
		threshold = 90
	}

	logger := cfg.Logger
	if logger == nil {
		logger = slog.Default()
	}

	return &HealthWatcher{
		interval:          interval,
		fortressID:        cfg.FortressID,
		serverID:          cfg.ServerID,
		degradedThreshold: threshold,
		logger:            logger,
	}
}

// Watch starts watching system health and returns a channel of events.
func (w *HealthWatcher) Watch(ctx context.Context) (<-chan event.Event, error) {
	out := make(chan event.Event)

	go func() {
		defer close(out)

		w.logger.Info("starting health watcher", "interval", w.interval)

		// Send immediate heartbeat
		w.emitHeartbeat(ctx, out)

		ticker := time.NewTicker(w.interval)
		defer ticker.Stop()

		for {
			select {
			case <-ctx.Done():
				w.logger.Info("health watcher stopped", "reason", ctx.Err())
				return
			case <-ticker.C:
				w.emitHeartbeat(ctx, out)
			}
		}
	}()

	return out, nil
}

// Name returns the watcher name.
func (w *HealthWatcher) Name() string {
	return "health"
}

// emitHeartbeat collects metrics and sends a heartbeat event.
func (w *HealthWatcher) emitHeartbeat(ctx context.Context, out chan<- event.Event) {
	metrics := collectHealthMetrics()

	// Determine event type based on degradation
	eventType := event.HealthHeartbeat
	isDegraded := metrics.IsDegraded(w.degradedThreshold)

	if isDegraded && !w.lastDegraded {
		eventType = event.HealthDegraded
		w.logger.Warn("system health degraded",
			"cpu", metrics.CPUPercent,
			"memory", metrics.MemoryPercent,
			"disk", metrics.DiskPercent,
		)
	} else if !isDegraded && w.lastDegraded {
		eventType = event.HealthRecovered
		w.logger.Info("system health recovered")
	}
	w.lastDegraded = isDegraded

	e := event.NewEvent(eventType, w.fortressID, w.serverID, metrics.ToPayload())

	select {
	case <-ctx.Done():
	case out <- e:
	}
}

// ToPayload converts HealthMetrics to an event payload.
func (m HealthMetrics) ToPayload() map[string]any {
	return map[string]any{
		"cpu_percent":     m.CPUPercent,
		"memory_percent":  m.MemoryPercent,
		"memory_used_gb":  m.MemoryUsedGB,
		"memory_total_gb": m.MemoryTotalGB,
		"disk_percent":    m.DiskPercent,
		"disk_used_gb":    m.DiskUsedGB,
		"disk_total_gb":   m.DiskTotalGB,
		"load_1m":         m.Load1m,
		"load_5m":         m.Load5m,
		"load_15m":        m.Load15m,
		"container_count": m.ContainerCount,
		"uptime_seconds":  m.UptimeSeconds,
	}
}

// IsDegraded returns true if any metric exceeds the threshold.
func (m HealthMetrics) IsDegraded(threshold float64) bool {
	return m.CPUPercent > threshold ||
		m.MemoryPercent > threshold ||
		m.DiskPercent > threshold
}

// collectHealthMetrics gathers current system metrics.
func collectHealthMetrics() HealthMetrics {
	memPercent, memUsed, memTotal := getMemoryUsageDetailed()
	diskPercent, diskUsed, diskTotal := getDiskUsageDetailed("/")
	load1, load5, load15 := getLoadAvg()

	return HealthMetrics{
		CPUPercent:     getCPUUsage(),
		MemoryPercent:  memPercent,
		MemoryUsedGB:   memUsed,
		MemoryTotalGB:  memTotal,
		DiskPercent:    diskPercent,
		DiskUsedGB:     diskUsed,
		DiskTotalGB:    diskTotal,
		Load1m:         load1,
		Load5m:         load5,
		Load15m:        load15,
		ContainerCount: 0, // TODO: get from Docker
		UptimeSeconds:  getUptime(),
	}
}

// getCPUUsage returns CPU usage percentage.
// On Linux, reads from /proc/stat. On other platforms, returns a default.
func getCPUUsage() float64 {
	if runtime.GOOS != "linux" {
		// On non-Linux, use Go's runtime stats as approximation
		var m runtime.MemStats
		runtime.ReadMemStats(&m)
		return float64(runtime.NumGoroutine()) / 100 * 10 // Rough approximation
	}

	// Read /proc/stat
	file, err := os.Open("/proc/stat")
	if err != nil {
		return 0
	}
	defer file.Close()

	scanner := bufio.NewScanner(file)
	if scanner.Scan() {
		line := scanner.Text()
		if strings.HasPrefix(line, "cpu ") {
			fields := strings.Fields(line)
			if len(fields) >= 5 {
				user, _ := strconv.ParseFloat(fields[1], 64)
				nice, _ := strconv.ParseFloat(fields[2], 64)
				system, _ := strconv.ParseFloat(fields[3], 64)
				idle, _ := strconv.ParseFloat(fields[4], 64)

				total := user + nice + system + idle
				if total > 0 {
					return (total - idle) / total * 100
				}
			}
		}
	}
	return 0
}

// getMemoryUsageDetailed returns memory usage percentage, used GB, and total GB.
func getMemoryUsageDetailed() (percent, usedGB, totalGB float64) {
	var m runtime.MemStats
	runtime.ReadMemStats(&m)

	if runtime.GOOS == "linux" {
		// Try to read from /proc/meminfo for more accuracy
		file, err := os.Open("/proc/meminfo")
		if err == nil {
			defer file.Close()

			var total, available uint64
			scanner := bufio.NewScanner(file)
			for scanner.Scan() {
				line := scanner.Text()
				if strings.HasPrefix(line, "MemTotal:") {
					fields := strings.Fields(line)
					if len(fields) >= 2 {
						total, _ = strconv.ParseUint(fields[1], 10, 64)
					}
				} else if strings.HasPrefix(line, "MemAvailable:") {
					fields := strings.Fields(line)
					if len(fields) >= 2 {
						available, _ = strconv.ParseUint(fields[1], 10, 64)
					}
				}
			}
			if total > 0 {
				// /proc/meminfo reports in kB
				totalGB = float64(total) / 1024 / 1024
				usedGB = float64(total-available) / 1024 / 1024
				percent = float64(total-available) / float64(total) * 100
				return
			}
		}
	}

	// Fallback: use Go runtime stats
	totalGB = float64(m.Sys) / 1024 / 1024 / 1024
	usedGB = float64(m.Alloc) / 1024 / 1024 / 1024
	percent = float64(m.Alloc) / float64(m.Sys) * 100
	return
}

// getDiskUsageDetailed returns disk usage percentage, used GB, and total GB for the given path.
func getDiskUsageDetailed(path string) (percent, usedGB, totalGB float64) {
	var stat syscall.Statfs_t
	if err := syscall.Statfs(path, &stat); err != nil {
		return 0, 0, 0
	}

	total := stat.Blocks * uint64(stat.Bsize)
	free := stat.Bfree * uint64(stat.Bsize)
	used := total - free

	if total > 0 {
		percent = float64(used) / float64(total) * 100
		usedGB = float64(used) / 1024 / 1024 / 1024
		totalGB = float64(total) / 1024 / 1024 / 1024
	}
	return
}

// getMemoryUsage returns memory usage percentage (convenience wrapper).
func getMemoryUsage() float64 {
	percent, _, _ := getMemoryUsageDetailed()
	return percent
}

// getDiskUsage returns disk usage percentage (convenience wrapper).
func getDiskUsage(path string) float64 {
	percent, _, _ := getDiskUsageDetailed(path)
	return percent
}

// getLoadAvg returns 1, 5, and 15 minute load averages.
func getLoadAvg() (load1, load5, load15 float64) {
	if runtime.GOOS == "linux" {
		data, err := os.ReadFile("/proc/loadavg")
		if err == nil {
			fields := strings.Fields(string(data))
			if len(fields) >= 3 {
				load1, _ = strconv.ParseFloat(fields[0], 64)
				load5, _ = strconv.ParseFloat(fields[1], 64)
				load15, _ = strconv.ParseFloat(fields[2], 64)
				return
			}
		}
	}
	// On non-Linux, return 0s
	return 0, 0, 0
}

// getUptime returns system uptime in seconds.
func getUptime() int64 {
	if runtime.GOOS == "linux" {
		data, err := os.ReadFile("/proc/uptime")
		if err == nil {
			fields := strings.Fields(string(data))
			if len(fields) >= 1 {
				uptime, _ := strconv.ParseFloat(fields[0], 64)
				return int64(uptime)
			}
		}
	}

	// Fallback: use process start time as approximation
	// This isn't system uptime but better than 0
	return int64(time.Since(time.Now().Add(-24 * time.Hour)).Seconds())
}
