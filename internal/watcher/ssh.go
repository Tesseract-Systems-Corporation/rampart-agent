package watcher

import (
	"bufio"
	"context"
	"fmt"
	"io"
	"log/slog"
	"os"
	"regexp"
	"time"

	"github.com/Tesseract-Systems-Corporation/rampart-agent/pkg/event"
)

// SSHConfig holds configuration for the SSH watcher.
type SSHConfig struct {
	// LogPath is the path to the auth log file.
	// Defaults to /var/log/auth.log if empty.
	LogPath string

	// FortressID is the ID of the Fortress this agent belongs to.
	FortressID string

	// ServerID is the ID of this server.
	ServerID string

	// Logger is the logger to use. If nil, uses slog.Default().
	Logger *slog.Logger
}

// SSHWatcher monitors SSH authentication events from auth logs.
type SSHWatcher struct {
	logPath    string
	fortressID string
	serverID   string
	logger     *slog.Logger

	// Deduplication: track recent events to avoid duplicates
	recentEvents map[string]time.Time
}

// dedupWindow is how long to consider events as duplicates
const dedupWindow = 2 * time.Second

// dedupCleanupInterval is how often to clean up old dedup entries
const dedupCleanupInterval = 30 * time.Second

// NewSSHWatcher creates a new SSHWatcher with the given configuration.
func NewSSHWatcher(cfg SSHConfig) *SSHWatcher {
	logPath := cfg.LogPath
	if logPath == "" {
		logPath = "/var/log/auth.log"
	}

	logger := cfg.Logger
	if logger == nil {
		logger = slog.Default()
	}

	return &SSHWatcher{
		logPath:      logPath,
		fortressID:   cfg.FortressID,
		serverID:     cfg.ServerID,
		logger:       logger,
		recentEvents: make(map[string]time.Time),
	}
}

// Watch starts watching SSH authentication events.
func (w *SSHWatcher) Watch(ctx context.Context) (<-chan event.Event, error) {
	out := make(chan event.Event)

	// Start cleanup goroutine
	go func() {
		ticker := time.NewTicker(dedupCleanupInterval)
		defer ticker.Stop()
		for {
			select {
			case <-ctx.Done():
				return
			case <-ticker.C:
				w.cleanupOldEvents()
			}
		}
	}()

	go func() {
		defer close(out)

		w.logger.Info("starting ssh watcher", "log_path", w.logPath)

		for {
			select {
			case <-ctx.Done():
				w.logger.Info("ssh watcher stopped", "reason", ctx.Err())
				return
			default:
			}

			if err := w.tailLog(ctx, out); err != nil {
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
func (w *SSHWatcher) Name() string {
	return "ssh"
}

// isDuplicate checks if an event with the given key was seen recently.
// Returns true if duplicate, false if new (and records it).
func (w *SSHWatcher) isDuplicate(key string) bool {
	now := time.Now()
	if lastSeen, exists := w.recentEvents[key]; exists {
		if now.Sub(lastSeen) < dedupWindow {
			return true
		}
	}
	w.recentEvents[key] = now
	return false
}

// cleanupOldEvents removes entries older than dedupWindow.
func (w *SSHWatcher) cleanupOldEvents() {
	now := time.Now()
	for key, lastSeen := range w.recentEvents {
		if now.Sub(lastSeen) > dedupWindow {
			delete(w.recentEvents, key)
		}
	}
}

// tailLog opens and tails the auth log file.
func (w *SSHWatcher) tailLog(ctx context.Context, out chan<- event.Event) error {
	file, err := os.Open(w.logPath)
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

		e := parseSSHLogLine(line, w.fortressID, w.serverID)
		if e != nil {
			// Create dedup key from event payload
			dedupKey := fmt.Sprintf("%s:%s:%s:%v",
				e.Payload["user"],
				e.Payload["source_ip"],
				e.Payload["auth_method"],
				e.Payload["success"],
			)

			if w.isDuplicate(dedupKey) {
				w.logger.Debug("skipping duplicate ssh event", "key", dedupKey)
				continue
			}

			w.logger.Debug("ssh event",
				"user", e.Payload["user"],
				"success", e.Payload["success"],
				"source_ip", e.Payload["source_ip"],
			)

			select {
			case <-ctx.Done():
				return ctx.Err()
			case out <- *e:
			}
		}
	}
}

// Regex patterns for parsing SSH log lines
var (
	// Matches: "Accepted publickey for jordan from 192.168.1.100 port 54321"
	acceptedKeyRe = regexp.MustCompile(`Accepted publickey for (\S+) from (\S+) port \d+`)

	// Matches: "Accepted password for admin from 10.0.0.5 port 22"
	acceptedPasswordRe = regexp.MustCompile(`Accepted password for (\S+) from (\S+) port \d+`)

	// Matches: "Failed password for invalid user hacker from 1.2.3.4 port 22"
	// Also matches: "Failed password for root from 1.2.3.4 port 22"
	failedPasswordRe = regexp.MustCompile(`Failed password for (?:invalid user )?(\S+) from (\S+) port \d+`)

	// Matches: "Failed publickey for root from 5.6.7.8 port 22"
	failedKeyRe = regexp.MustCompile(`Failed publickey for (\S+) from (\S+) port \d+`)
)

// parseSSHLogLine parses a single line from the auth log.
// Returns nil if the line is not an SSH authentication event.
func parseSSHLogLine(line, fortressID, serverID string) *event.Event {
	var user, ip, method string
	var success bool

	if matches := acceptedKeyRe.FindStringSubmatch(line); matches != nil {
		user = matches[1]
		ip = matches[2]
		method = "key"
		success = true
	} else if matches := acceptedPasswordRe.FindStringSubmatch(line); matches != nil {
		user = matches[1]
		ip = matches[2]
		method = "password"
		success = true
	} else if matches := failedPasswordRe.FindStringSubmatch(line); matches != nil {
		user = matches[1]
		ip = matches[2]
		method = "password"
		success = false
	} else if matches := failedKeyRe.FindStringSubmatch(line); matches != nil {
		user = matches[1]
		ip = matches[2]
		method = "key"
		success = false
	} else {
		return nil
	}

	e := event.NewEvent(event.AccessSSH, fortressID, serverID, map[string]any{
		"user":        user,
		"source_ip":   ip,
		"auth_method": method,
		"success":     success,
	})

	e.Actor = &event.Actor{
		Type: event.ActorTypeUser,
		Name: user,
		IP:   ip,
	}

	return &e
}
