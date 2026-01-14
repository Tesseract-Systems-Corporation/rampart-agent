package watcher

import (
	"context"
	"log/slog"
	"net"
	"os"
	"os/exec"
	"regexp"
	"strconv"
	"strings"
	"time"

	"github.com/Tesseract-Systems-Corporation/rampart-agent/pkg/event"
)

// PostgresConfig configures the Postgres detection watcher.
type PostgresConfig struct {
	ScanInterval time.Duration
	FortressID   string
	ServerID     string
	Logger       *slog.Logger
}

// PostgresWatcher detects PostgreSQL instances running on the server.
type PostgresWatcher struct {
	config    PostgresConfig
	detected  map[string]bool // host:port -> detected
	logger    *slog.Logger
}

// DetectedPostgres represents a detected PostgreSQL instance.
type DetectedPostgres struct {
	Host        string
	Port        int
	Version     string
	DetectedVia string // "process", "socket", "docker", "port"
}

// NewPostgresWatcher creates a new Postgres detection watcher.
func NewPostgresWatcher(cfg PostgresConfig) *PostgresWatcher {
	if cfg.ScanInterval == 0 {
		cfg.ScanInterval = 5 * time.Minute
	}
	if cfg.Logger == nil {
		cfg.Logger = slog.Default()
	}

	return &PostgresWatcher{
		config:   cfg,
		detected: make(map[string]bool),
		logger:   cfg.Logger.With("watcher", "postgres"),
	}
}

// Watch starts the Postgres detection watcher.
func (w *PostgresWatcher) Watch(ctx context.Context) (<-chan event.Event, error) {
	ch := make(chan event.Event, 50)

	go w.run(ctx, ch)

	return ch, nil
}

func (w *PostgresWatcher) run(ctx context.Context, ch chan<- event.Event) {
	defer close(ch)

	// Initial scan
	w.scan(ctx, ch)

	ticker := time.NewTicker(w.config.ScanInterval)
	defer ticker.Stop()

	for {
		select {
		case <-ctx.Done():
			return
		case <-ticker.C:
			w.scan(ctx, ch)
		}
	}
}

func (w *PostgresWatcher) scan(ctx context.Context, ch chan<- event.Event) {
	instances := w.detectPostgres(ctx)

	for _, inst := range instances {
		key := inst.Host + ":" + strconv.Itoa(inst.Port)
		if !w.detected[key] {
			w.detected[key] = true

			ev := event.NewEvent(event.PGDatabaseDetected, w.config.FortressID, w.config.ServerID, map[string]any{
				"host":         inst.Host,
				"port":         inst.Port,
				"version":      inst.Version,
				"detected_via": inst.DetectedVia,
			})
			ch <- ev

			w.logger.Info("detected postgres instance",
				"host", inst.Host,
				"port", inst.Port,
				"version", inst.Version,
				"via", inst.DetectedVia,
			)
		}
	}
}

func (w *PostgresWatcher) detectPostgres(ctx context.Context) []DetectedPostgres {
	var instances []DetectedPostgres

	// Method 1: Check for running postgres processes
	if procs := w.detectFromProcess(); len(procs) > 0 {
		instances = append(instances, procs...)
	}

	// Method 2: Check for Unix sockets
	if sockets := w.detectFromSocket(); len(sockets) > 0 {
		instances = append(instances, sockets...)
	}

	// Method 3: Check Docker containers
	if docker := w.detectFromDocker(ctx); len(docker) > 0 {
		instances = append(instances, docker...)
	}

	// Method 4: Check common ports
	if ports := w.detectFromPorts(); len(ports) > 0 {
		instances = append(instances, ports...)
	}

	// Deduplicate by host:port
	seen := make(map[string]bool)
	var unique []DetectedPostgres
	for _, inst := range instances {
		key := inst.Host + ":" + strconv.Itoa(inst.Port)
		if !seen[key] {
			seen[key] = true
			unique = append(unique, inst)
		}
	}

	return unique
}

func (w *PostgresWatcher) detectFromProcess() []DetectedPostgres {
	var instances []DetectedPostgres

	// Try pgrep first
	out, err := exec.Command("pgrep", "-x", "postgres").Output()
	if err != nil {
		return instances
	}

	if len(out) > 0 {
		// Found postgres process, try to get version
		version := ""
		if verOut, err := exec.Command("postgres", "--version").Output(); err == nil {
			// Parse version from "postgres (PostgreSQL) 14.5"
			versionRegex := regexp.MustCompile(`PostgreSQL\)?\s+([\d.]+)`)
			if matches := versionRegex.FindSubmatch(verOut); len(matches) > 1 {
				version = string(matches[1])
			}
		}

		instances = append(instances, DetectedPostgres{
			Host:        "localhost",
			Port:        5432, // Default port
			Version:     version,
			DetectedVia: "process",
		})
	}

	return instances
}

func (w *PostgresWatcher) detectFromSocket() []DetectedPostgres {
	var instances []DetectedPostgres

	// Common PostgreSQL Unix socket paths
	socketPaths := []string{
		"/var/run/postgresql/.s.PGSQL.5432",
		"/tmp/.s.PGSQL.5432",
		"/var/lib/postgresql/.s.PGSQL.5432",
	}

	for _, path := range socketPaths {
		if _, err := os.Stat(path); err == nil {
			// Extract port from socket path
			port := 5432
			portRegex := regexp.MustCompile(`\.s\.PGSQL\.(\d+)`)
			if matches := portRegex.FindStringSubmatch(path); len(matches) > 1 {
				if p, err := strconv.Atoi(matches[1]); err == nil {
					port = p
				}
			}

			instances = append(instances, DetectedPostgres{
				Host:        "localhost",
				Port:        port,
				DetectedVia: "socket",
			})
			break // Only add once per host
		}
	}

	return instances
}

func (w *PostgresWatcher) detectFromDocker(ctx context.Context) []DetectedPostgres {
	var instances []DetectedPostgres

	// Check if Docker is available
	if _, err := exec.LookPath("docker"); err != nil {
		return instances
	}

	// List running containers with postgres image
	out, err := exec.CommandContext(ctx, "docker", "ps", "--format", "{{.ID}}:{{.Image}}:{{.Ports}}").Output()
	if err != nil {
		return instances
	}

	lines := strings.Split(string(out), "\n")
	for _, line := range lines {
		if strings.TrimSpace(line) == "" {
			continue
		}

		parts := strings.SplitN(line, ":", 3)
		if len(parts) < 2 {
			continue
		}

		image := strings.ToLower(parts[1])
		if !strings.Contains(image, "postgres") {
			continue
		}

		// Parse ports: "0.0.0.0:5432->5432/tcp"
		port := 5432
		if len(parts) > 2 {
			portStr := parts[2]
			portRegex := regexp.MustCompile(`(\d+)->5432`)
			if matches := portRegex.FindStringSubmatch(portStr); len(matches) > 1 {
				if p, err := strconv.Atoi(matches[1]); err == nil {
					port = p
				}
			}
		}

		// Try to get version from container
		version := ""
		containerID := parts[0]
		if verOut, err := exec.CommandContext(ctx, "docker", "exec", containerID, "postgres", "--version").Output(); err == nil {
			versionRegex := regexp.MustCompile(`PostgreSQL\)?\s+([\d.]+)`)
			if matches := versionRegex.FindSubmatch(verOut); len(matches) > 1 {
				version = string(matches[1])
			}
		}

		instances = append(instances, DetectedPostgres{
			Host:        "localhost",
			Port:        port,
			Version:     version,
			DetectedVia: "docker",
		})
	}

	return instances
}

func (w *PostgresWatcher) detectFromPorts() []DetectedPostgres {
	var instances []DetectedPostgres

	// Check common Postgres ports
	ports := []int{5432, 5433, 5434}

	for _, port := range ports {
		addr := "localhost:" + strconv.Itoa(port)
		conn, err := net.DialTimeout("tcp", addr, 2*time.Second)
		if err == nil {
			conn.Close()
			instances = append(instances, DetectedPostgres{
				Host:        "localhost",
				Port:        port,
				DetectedVia: "port",
			})
		}
	}

	return instances
}
