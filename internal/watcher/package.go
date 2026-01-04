package watcher

import (
	"bufio"
	"context"
	"io"
	"log/slog"
	"os"
	"regexp"
	"strings"
	"time"

	"github.com/Tesseract-Systems-Corporation/rampart-agent/pkg/event"
)

// PackageConfig holds configuration for the Package watcher.
type PackageConfig struct {
	// AptLogPaths is a list of paths to check for apt/dpkg log files.
	// The first existing path will be used.
	// Defaults to ["/var/log/dpkg.log"] if empty.
	AptLogPaths []string

	// YumLogPaths is a list of paths to check for yum/dnf log files.
	// The first existing path will be used.
	// Defaults to ["/var/log/dnf.log", "/var/log/yum.log"] if empty.
	YumLogPaths []string

	// FortressID is the ID of the Fortress this agent belongs to.
	FortressID string

	// ServerID is the ID of this server.
	ServerID string

	// Logger is the logger to use. If nil, uses slog.Default().
	Logger *slog.Logger
}

// PackageWatcher monitors package installations, upgrades, and removals.
type PackageWatcher struct {
	aptLogPaths    []string
	yumLogPaths    []string
	fortressID     string
	serverID       string
	logger         *slog.Logger
	packageManager string // "apt", "yum", "dnf", or ""
}

// NewPackageWatcher creates a new PackageWatcher with the given configuration.
func NewPackageWatcher(cfg PackageConfig) *PackageWatcher {
	aptLogPaths := cfg.AptLogPaths
	if len(aptLogPaths) == 0 {
		aptLogPaths = []string{"/var/log/dpkg.log", "/var/log/apt/history.log"}
	}

	yumLogPaths := cfg.YumLogPaths
	if len(yumLogPaths) == 0 {
		yumLogPaths = []string{"/var/log/dnf.log", "/var/log/yum.log"}
	}

	logger := cfg.Logger
	if logger == nil {
		logger = slog.Default()
	}

	return &PackageWatcher{
		aptLogPaths: aptLogPaths,
		yumLogPaths: yumLogPaths,
		fortressID:  cfg.FortressID,
		serverID:    cfg.ServerID,
		logger:      logger,
	}
}

// Watch starts watching package events.
func (w *PackageWatcher) Watch(ctx context.Context) (<-chan event.Event, error) {
	out := make(chan event.Event)

	go func() {
		defer close(out)

		// Detect which package manager is in use
		logPath, pkgManager := w.detectPackageManager()
		if logPath == "" {
			w.logger.Warn("no package manager log found, package watcher disabled")
			<-ctx.Done()
			return
		}

		w.packageManager = pkgManager
		w.logger.Info("starting package watcher", "log_path", logPath, "package_manager", pkgManager)

		for {
			select {
			case <-ctx.Done():
				w.logger.Info("package watcher stopped", "reason", ctx.Err())
				return
			default:
			}

			if err := w.tailLog(ctx, out, logPath); err != nil {
				if ctx.Err() != nil {
					return
				}
				w.logger.Error("error tailing log", "error", err)
				// Wait before retrying
				select {
				case <-ctx.Done():
					return
				case <-time.After(5 * time.Second):
				}
			}
		}
	}()

	return out, nil
}

// Name returns the watcher name.
func (w *PackageWatcher) Name() string {
	return "package"
}

// detectPackageManager checks which package manager is available and returns
// the log path to monitor along with the package manager name.
func (w *PackageWatcher) detectPackageManager() (logPath, pkgManager string) {
	// Check for apt/dpkg (Debian/Ubuntu) first - iterate through configured paths
	for _, path := range w.aptLogPaths {
		if _, err := os.Stat(path); err == nil {
			return path, "apt"
		}
	}

	// Check for yum/dnf (RHEL/CentOS/Fedora) - iterate through configured paths
	for _, path := range w.yumLogPaths {
		if _, err := os.Stat(path); err == nil {
			// Determine if it's dnf or yum based on the path
			if strings.Contains(path, "dnf") {
				return path, "dnf"
			}
			return path, "yum"
		}
	}

	return "", ""
}

// tailLog opens and tails the package log file.
func (w *PackageWatcher) tailLog(ctx context.Context, out chan<- event.Event, logPath string) error {
	file, err := os.Open(logPath)
	if err != nil {
		return err
	}
	defer file.Close()

	// Seek to end of file to only get new entries
	if _, err := file.Seek(0, io.SeekEnd); err != nil {
		return err
	}

	reader := bufio.NewReader(file)

	for {
		select {
		case <-ctx.Done():
			return ctx.Err()
		default:
		}

		line, err := reader.ReadString('\n')
		if err != nil {
			if err == io.EOF {
				// No new data, wait a bit
				select {
				case <-ctx.Done():
					return ctx.Err()
				case <-time.After(100 * time.Millisecond):
				}
				continue
			}
			return err
		}

		var e *event.Event
		switch w.packageManager {
		case "apt":
			e = parseDpkgLogLine(line, w.fortressID, w.serverID)
		case "yum", "dnf":
			e = parseYumLogLine(line, w.fortressID, w.serverID, w.packageManager)
		}

		if e != nil {
			w.logger.Debug("package event",
				"type", e.Type,
				"package", e.Payload["package_name"],
			)

			select {
			case <-ctx.Done():
				return ctx.Err()
			case out <- *e:
			}
		}
	}
}

// Regex patterns for parsing dpkg log lines
// Format: 2024-01-15 10:30:45 install nginx:amd64 <none> 1.18.0-0ubuntu1
//
//	2024-01-15 10:31:00 upgrade openssl:amd64 1.1.1f-1ubuntu2.19 1.1.1f-1ubuntu2.20
//	2024-01-15 10:32:00 remove apache2:amd64 2.4.41-4ubuntu3.14 <none>
var dpkgLogRe = regexp.MustCompile(`^(\d{4}-\d{2}-\d{2} \d{2}:\d{2}:\d{2}) (install|upgrade|remove) (\S+) (\S+) (\S+)`)

// parseDpkgLogLine parses a single line from the dpkg log.
// Returns nil if the line is not a package event.
func parseDpkgLogLine(line, fortressID, serverID string) *event.Event {
	matches := dpkgLogRe.FindStringSubmatch(line)
	if matches == nil {
		return nil
	}

	// timestamp := matches[1] // Could be parsed if needed
	action := matches[2]
	packageWithArch := matches[3]
	previousVersion := matches[4]
	newVersion := matches[5]

	// Extract package name without architecture (e.g., "nginx:amd64" -> "nginx")
	packageName := packageWithArch
	if idx := strings.Index(packageWithArch, ":"); idx != -1 {
		packageName = packageWithArch[:idx]
	}

	// Clean up version strings
	if previousVersion == "<none>" {
		previousVersion = ""
	}
	if newVersion == "<none>" {
		newVersion = ""
	}

	var eventType event.EventType
	switch action {
	case "install":
		eventType = event.PackageInstalled
	case "upgrade":
		eventType = event.PackageUpgraded
	case "remove":
		eventType = event.PackageRemoved
	default:
		return nil
	}

	payload := map[string]any{
		"package_manager": "apt",
		"package_name":    packageName,
	}

	if previousVersion != "" {
		payload["previous_version"] = previousVersion
	}
	if newVersion != "" {
		payload["new_version"] = newVersion
	}

	e := event.NewEvent(eventType, fortressID, serverID, payload)

	e.Actor = &event.Actor{
		Type: event.ActorTypeSystem,
		Name: "apt",
	}

	return &e
}

// Regex patterns for parsing yum/dnf log lines
// Format: Jan 15 10:30:45 Installed: nginx-1.18.0-1.el8.x86_64
//
//	Jan 15 10:31:00 Updated: openssl-1.1.1k-5.el8.x86_64
//	Jan 15 10:32:00 Erased: httpd-2.4.37-43.el8.x86_64
var yumLogRe = regexp.MustCompile(`^(\w{3}\s+\d{1,2}\s+\d{2}:\d{2}:\d{2})\s+(Installed|Updated|Erased):\s+(\S+)`)

// parseYumLogLine parses a single line from the yum/dnf log.
// Returns nil if the line is not a package event.
func parseYumLogLine(line, fortressID, serverID, pkgManager string) *event.Event {
	matches := yumLogRe.FindStringSubmatch(line)
	if matches == nil {
		return nil
	}

	// timestamp := matches[1] // Could be parsed if needed
	action := matches[2]
	packageWithVersion := matches[3]

	// Parse package name and version from format like "nginx-1.18.0-1.el8.x86_64"
	packageName, version := parseYumPackageString(packageWithVersion)

	var eventType event.EventType
	switch action {
	case "Installed":
		eventType = event.PackageInstalled
	case "Updated":
		eventType = event.PackageUpgraded
	case "Erased":
		eventType = event.PackageRemoved
	default:
		return nil
	}

	payload := map[string]any{
		"package_manager": pkgManager,
		"package_name":    packageName,
	}

	// For updates, we only know the new version from the log
	// For installs, it's the new version
	// For removals, it's the previous version
	if action == "Erased" {
		if version != "" {
			payload["previous_version"] = version
		}
	} else {
		if version != "" {
			payload["new_version"] = version
		}
	}

	e := event.NewEvent(eventType, fortressID, serverID, payload)

	e.Actor = &event.Actor{
		Type: event.ActorTypeSystem,
		Name: pkgManager,
	}

	return &e
}

// parseYumPackageString parses a yum/dnf package string like "nginx-1.18.0-1.el8.x86_64"
// into package name and version. Returns (packageName, version).
func parseYumPackageString(pkgStr string) (string, string) {
	// Remove architecture suffix if present
	parts := strings.Split(pkgStr, ".")
	if len(parts) > 1 {
		lastPart := parts[len(parts)-1]
		// Common architectures
		if lastPart == "x86_64" || lastPart == "i686" || lastPart == "noarch" ||
			lastPart == "aarch64" || lastPart == "armv7hl" {
			pkgStr = strings.Join(parts[:len(parts)-1], ".")
		}
	}

	// Find the last dash that separates name from version-release
	// Package names can contain dashes, so we look for the pattern where
	// the part after the dash starts with a digit (version number)
	lastDashIdx := -1
	for i := len(pkgStr) - 1; i >= 0; i-- {
		if pkgStr[i] == '-' {
			if i+1 < len(pkgStr) && isDigit(pkgStr[i+1]) {
				// This dash is followed by a digit, likely start of version
				// But we need to check one more dash back for the release number
				lastDashIdx = i
			}
		}
	}

	// Try to find the second-to-last dash for packages like nginx-1.18.0-1
	if lastDashIdx > 0 {
		for i := lastDashIdx - 1; i >= 0; i-- {
			if pkgStr[i] == '-' {
				if i+1 < len(pkgStr) && isDigit(pkgStr[i+1]) {
					lastDashIdx = i
					break
				}
			}
		}
	}

	if lastDashIdx > 0 {
		return pkgStr[:lastDashIdx], pkgStr[lastDashIdx+1:]
	}

	return pkgStr, ""
}

func isDigit(b byte) bool {
	return b >= '0' && b <= '9'
}
