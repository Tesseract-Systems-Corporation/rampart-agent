package watcher

import (
	"context"
	"runtime"
	"testing"
	"time"

	"github.com/Tesseract-Systems-Corporation/rampart-agent/pkg/event"
)

func TestHealthWatcherInterface(t *testing.T) {
	var _ Watcher = (*HealthWatcher)(nil)
}

func TestHealthWatcherName(t *testing.T) {
	w := NewHealthWatcher(HealthConfig{
		FortressID: "fort_test",
		ServerID:   "srv_test",
	})
	if w.Name() != "health" {
		t.Errorf("Name() = %v, want health", w.Name())
	}
}

func TestHealthWatcherConfig(t *testing.T) {
	tests := []struct {
		name         string
		config       HealthConfig
		wantInterval time.Duration
	}{
		{
			name: "default interval",
			config: HealthConfig{
				FortressID: "fort_test",
				ServerID:   "srv_test",
			},
			wantInterval: DefaultHealthInterval,
		},
		{
			name: "custom interval for testing",
			config: HealthConfig{
				Interval:   60 * time.Second,
				FortressID: "fort_test",
				ServerID:   "srv_test",
			},
			wantInterval: 60 * time.Second,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			w := NewHealthWatcher(tt.config)
			if w.interval != tt.wantInterval {
				t.Errorf("interval = %v, want %v", w.interval, tt.wantInterval)
			}
		})
	}
}

func TestHealthWatcherEmitsHeartbeat(t *testing.T) {
	w := NewHealthWatcher(HealthConfig{
		Interval:   50 * time.Millisecond, // Fast interval for testing
		FortressID: "fort_test",
		ServerID:   "srv_test",
	})

	ctx, cancel := context.WithTimeout(context.Background(), 200*time.Millisecond)
	defer cancel()

	ch, err := w.Watch(ctx)
	if err != nil {
		t.Fatalf("Watch() error = %v", err)
	}

	var events []event.Event
	for e := range ch {
		events = append(events, e)
	}

	// Should have received at least 1 heartbeat (immediate + interval)
	if len(events) < 1 {
		t.Errorf("received %d events, want at least 1", len(events))
	}

	// Verify event structure
	if len(events) > 0 {
		e := events[0]
		if e.Type != event.HealthHeartbeat {
			t.Errorf("Type = %v, want %v", e.Type, event.HealthHeartbeat)
		}
		if e.FortressID != "fort_test" {
			t.Errorf("FortressID = %v, want fort_test", e.FortressID)
		}
		if e.ServerID != "srv_test" {
			t.Errorf("ServerID = %v, want srv_test", e.ServerID)
		}

		// Verify payload has required fields
		payload := e.Payload
		if _, ok := payload["cpu_percent"]; !ok {
			t.Error("payload missing cpu_percent")
		}
		if _, ok := payload["memory_percent"]; !ok {
			t.Error("payload missing memory_percent")
		}
		if _, ok := payload["disk_percent"]; !ok {
			t.Error("payload missing disk_percent")
		}
		if _, ok := payload["uptime_seconds"]; !ok {
			t.Error("payload missing uptime_seconds")
		}
	}
}

func TestCollectHealthMetrics(t *testing.T) {
	metrics := collectHealthMetrics()

	// CPU percent should be between 0 and 100
	if metrics.CPUPercent < 0 || metrics.CPUPercent > 100 {
		t.Errorf("CPUPercent = %v, want 0-100", metrics.CPUPercent)
	}

	// Memory percent should be between 0 and 100
	if metrics.MemoryPercent < 0 || metrics.MemoryPercent > 100 {
		t.Errorf("MemoryPercent = %v, want 0-100", metrics.MemoryPercent)
	}

	// Disk percent should be between 0 and 100
	if metrics.DiskPercent < 0 || metrics.DiskPercent > 100 {
		t.Errorf("DiskPercent = %v, want 0-100", metrics.DiskPercent)
	}

	// Uptime should be positive
	if metrics.UptimeSeconds <= 0 {
		t.Errorf("UptimeSeconds = %v, want > 0", metrics.UptimeSeconds)
	}
}

func TestHealthMetricsToPayload(t *testing.T) {
	metrics := HealthMetrics{
		CPUPercent:     45.5,
		MemoryPercent:  62.3,
		DiskPercent:    34.1,
		ContainerCount: 6,
		UptimeSeconds:  86400,
	}

	payload := metrics.ToPayload()

	if payload["cpu_percent"] != 45.5 {
		t.Errorf("cpu_percent = %v, want 45.5", payload["cpu_percent"])
	}
	if payload["memory_percent"] != 62.3 {
		t.Errorf("memory_percent = %v, want 62.3", payload["memory_percent"])
	}
	if payload["disk_percent"] != 34.1 {
		t.Errorf("disk_percent = %v, want 34.1", payload["disk_percent"])
	}
	if payload["container_count"] != 6 {
		t.Errorf("container_count = %v, want 6", payload["container_count"])
	}
	if payload["uptime_seconds"] != int64(86400) {
		t.Errorf("uptime_seconds = %v, want 86400", payload["uptime_seconds"])
	}
}

func TestHealthWatcherContextCancellation(t *testing.T) {
	w := NewHealthWatcher(HealthConfig{
		Interval:   1 * time.Hour, // Long interval
		FortressID: "fort_test",
		ServerID:   "srv_test",
	})

	ctx, cancel := context.WithCancel(context.Background())

	ch, err := w.Watch(ctx)
	if err != nil {
		t.Fatalf("Watch() error = %v", err)
	}

	// Receive the immediate heartbeat
	select {
	case <-ch:
	case <-time.After(100 * time.Millisecond):
		t.Fatal("timeout waiting for initial heartbeat")
	}

	// Cancel context
	cancel()

	// Channel should close
	select {
	case _, ok := <-ch:
		if ok {
			// Might receive one more event, that's ok
			for range ch {
			}
		}
	case <-time.After(100 * time.Millisecond):
		t.Error("channel did not close after context cancellation")
	}
}

func TestGetCPUUsage(t *testing.T) {
	// Skip on non-Linux for now since /proc/stat doesn't exist
	if runtime.GOOS != "linux" {
		t.Skip("skipping CPU test on non-Linux")
	}

	cpu := getCPUUsage()
	if cpu < 0 || cpu > 100 {
		t.Errorf("getCPUUsage() = %v, want 0-100", cpu)
	}
}

func TestGetMemoryUsage(t *testing.T) {
	// This should work on all platforms
	mem := getMemoryUsage()
	if mem < 0 || mem > 100 {
		t.Errorf("getMemoryUsage() = %v, want 0-100", mem)
	}
}

func TestGetDiskUsage(t *testing.T) {
	disk := getDiskUsage("/")
	if disk < 0 || disk > 100 {
		t.Errorf("getDiskUsage() = %v, want 0-100", disk)
	}
}

func TestGetUptime(t *testing.T) {
	uptime := getUptime()
	// Uptime should be at least 1 second (system has been running)
	if uptime < 1 {
		t.Errorf("getUptime() = %v, want >= 1", uptime)
	}
}

func TestHealthThresholds(t *testing.T) {
	tests := []struct {
		name         string
		metrics      HealthMetrics
		wantDegraded bool
	}{
		{
			name: "healthy system",
			metrics: HealthMetrics{
				CPUPercent:    50,
				MemoryPercent: 50,
				DiskPercent:   50,
			},
			wantDegraded: false,
		},
		{
			name: "high cpu",
			metrics: HealthMetrics{
				CPUPercent:    95,
				MemoryPercent: 50,
				DiskPercent:   50,
			},
			wantDegraded: true,
		},
		{
			name: "high memory",
			metrics: HealthMetrics{
				CPUPercent:    50,
				MemoryPercent: 95,
				DiskPercent:   50,
			},
			wantDegraded: true,
		},
		{
			name: "high disk",
			metrics: HealthMetrics{
				CPUPercent:    50,
				MemoryPercent: 50,
				DiskPercent:   95,
			},
			wantDegraded: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			degraded := tt.metrics.IsDegraded(90) // 90% threshold
			if degraded != tt.wantDegraded {
				t.Errorf("IsDegraded() = %v, want %v", degraded, tt.wantDegraded)
			}
		})
	}
}

func TestHealthWatcherDegradedThreshold(t *testing.T) {
	tests := []struct {
		name          string
		config        HealthConfig
		wantThreshold float64
	}{
		{
			name: "default threshold",
			config: HealthConfig{
				FortressID: "fort_test",
				ServerID:   "srv_test",
			},
			wantThreshold: 90,
		},
		{
			name: "custom threshold",
			config: HealthConfig{
				DegradedThreshold: 80,
				FortressID:        "fort_test",
				ServerID:          "srv_test",
			},
			wantThreshold: 80,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			w := NewHealthWatcher(tt.config)
			if w.degradedThreshold != tt.wantThreshold {
				t.Errorf("degradedThreshold = %v, want %v", w.degradedThreshold, tt.wantThreshold)
			}
		})
	}
}

func TestHealthMetricsAllFields(t *testing.T) {
	metrics := HealthMetrics{
		CPUPercent:     50.5,
		MemoryPercent:  70.2,
		MemoryUsedGB:   8.5,
		MemoryTotalGB:  16.0,
		DiskPercent:    45.3,
		DiskUsedGB:     250.0,
		DiskTotalGB:    500.0,
		Load1m:         1.5,
		Load5m:         1.2,
		Load15m:        0.9,
		ContainerCount: 5,
		UptimeSeconds:  86400,
	}

	payload := metrics.ToPayload()

	if payload["cpu_percent"] != 50.5 {
		t.Errorf("cpu_percent = %v, want 50.5", payload["cpu_percent"])
	}
	if payload["memory_used_gb"] != 8.5 {
		t.Errorf("memory_used_gb = %v, want 8.5", payload["memory_used_gb"])
	}
	if payload["memory_total_gb"] != 16.0 {
		t.Errorf("memory_total_gb = %v, want 16.0", payload["memory_total_gb"])
	}
	if payload["disk_used_gb"] != 250.0 {
		t.Errorf("disk_used_gb = %v, want 250.0", payload["disk_used_gb"])
	}
	if payload["disk_total_gb"] != 500.0 {
		t.Errorf("disk_total_gb = %v, want 500.0", payload["disk_total_gb"])
	}
	if payload["load_1m"] != 1.5 {
		t.Errorf("load_1m = %v, want 1.5", payload["load_1m"])
	}
	if payload["load_5m"] != 1.2 {
		t.Errorf("load_5m = %v, want 1.2", payload["load_5m"])
	}
	if payload["load_15m"] != 0.9 {
		t.Errorf("load_15m = %v, want 0.9", payload["load_15m"])
	}
}

func TestDefaultHealthInterval(t *testing.T) {
	if DefaultHealthInterval != 30*time.Second {
		t.Errorf("DefaultHealthInterval = %v, want 30s", DefaultHealthInterval)
	}
}

func TestGetLoadAvg(t *testing.T) {
	if runtime.GOOS != "linux" {
		t.Skip("skipping load avg test on non-Linux")
	}

	load1, load5, load15 := getLoadAvg()

	// Load averages should be non-negative
	if load1 < 0 {
		t.Errorf("load1 = %v, want >= 0", load1)
	}
	if load5 < 0 {
		t.Errorf("load5 = %v, want >= 0", load5)
	}
	if load15 < 0 {
		t.Errorf("load15 = %v, want >= 0", load15)
	}
}

func TestGetMemoryUsageDetailed(t *testing.T) {
	percent, usedGB, totalGB := getMemoryUsageDetailed()

	// Percent should be between 0 and 100
	if percent < 0 || percent > 100 {
		t.Errorf("percent = %v, want 0-100", percent)
	}

	// Used should be less than or equal to total
	if usedGB > totalGB {
		t.Errorf("usedGB (%v) > totalGB (%v)", usedGB, totalGB)
	}

	// Total should be positive
	if totalGB <= 0 {
		t.Errorf("totalGB = %v, want > 0", totalGB)
	}
}

func TestGetDiskUsageDetailed(t *testing.T) {
	percent, usedGB, totalGB := getDiskUsageDetailed("/")

	// Percent should be between 0 and 100
	if percent < 0 || percent > 100 {
		t.Errorf("percent = %v, want 0-100", percent)
	}

	// Used should be less than or equal to total
	if usedGB > totalGB {
		t.Errorf("usedGB (%v) > totalGB (%v)", usedGB, totalGB)
	}

	// Total should be positive
	if totalGB <= 0 {
		t.Errorf("totalGB = %v, want > 0", totalGB)
	}
}

func TestIsDegradedBoundaryConditions(t *testing.T) {
	tests := []struct {
		name         string
		metrics      HealthMetrics
		threshold    float64
		wantDegraded bool
	}{
		{
			name: "exactly at threshold",
			metrics: HealthMetrics{
				CPUPercent:    90,
				MemoryPercent: 50,
				DiskPercent:   50,
			},
			threshold:    90,
			wantDegraded: false, // Not degraded at exactly threshold
		},
		{
			name: "just above threshold",
			metrics: HealthMetrics{
				CPUPercent:    90.1,
				MemoryPercent: 50,
				DiskPercent:   50,
			},
			threshold:    90,
			wantDegraded: true,
		},
		{
			name: "all at threshold",
			metrics: HealthMetrics{
				CPUPercent:    90,
				MemoryPercent: 90,
				DiskPercent:   90,
			},
			threshold:    90,
			wantDegraded: false,
		},
		{
			name: "zero threshold",
			metrics: HealthMetrics{
				CPUPercent:    0.1,
				MemoryPercent: 0.1,
				DiskPercent:   0.1,
			},
			threshold:    0,
			wantDegraded: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			degraded := tt.metrics.IsDegraded(tt.threshold)
			if degraded != tt.wantDegraded {
				t.Errorf("IsDegraded(%v) = %v, want %v", tt.threshold, degraded, tt.wantDegraded)
			}
		})
	}
}
