package watcher

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"io"
	"log/slog"
	"os"
	"path/filepath"
	"strings"
	"sync"

	"github.com/fsnotify/fsnotify"
	"github.com/Tesseract-Systems-Corporation/rampart-agent/pkg/event"
)

// SecretsConfig holds configuration for the Secrets watcher.
type SecretsConfig struct {
	// WatchPaths is the list of directories to watch for secret files.
	WatchPaths []string

	// SecretPatterns are filename patterns that indicate secret files.
	// Defaults to common patterns like .env, credentials, etc.
	SecretPatterns []string

	// FortressID is the ID of the Fortress this agent belongs to.
	FortressID string

	// ServerID is the ID of this server.
	ServerID string

	// Logger is the logger to use. If nil, uses slog.Default().
	Logger *slog.Logger
}

// SecretsWatcher monitors secret files for rotation and access patterns.
type SecretsWatcher struct {
	watchPaths     []string
	secretPatterns []string
	fortressID     string
	serverID       string
	logger         *slog.Logger

	// Track file hashes to detect rotation (content change)
	fileHashes map[string]string
	mu         sync.Mutex
}

// Default secret file patterns
var defaultSecretPatterns = []string{
	".env",
	".env.*",
	"*.pem",
	"*.key",
	"*.crt",
	"*.p12",
	"*.pfx",
	"credentials",
	"credentials.*",
	"secrets",
	"secrets.*",
	"*.secret",
	"id_rsa",
	"id_ed25519",
	"id_ecdsa",
	"authorized_keys",
	"known_hosts",
	"config.json",
	"service-account*.json",
	"*-credentials.json",
	"*-key.json",
	"token",
	"token.*",
	"*.token",
	"api_key*",
	"apikey*",
	"password*",
	"passwd",
	"shadow",
	"htpasswd",
	".htpasswd",
	"vault-token",
	"*.keystore",
	"*.jks",
}

// NewSecretsWatcher creates a new SecretsWatcher with the given configuration.
func NewSecretsWatcher(cfg SecretsConfig) *SecretsWatcher {
	patterns := cfg.SecretPatterns
	if len(patterns) == 0 {
		patterns = defaultSecretPatterns
	}

	logger := cfg.Logger
	if logger == nil {
		logger = slog.Default()
	}

	return &SecretsWatcher{
		watchPaths:     cfg.WatchPaths,
		secretPatterns: patterns,
		fortressID:     cfg.FortressID,
		serverID:       cfg.ServerID,
		logger:         logger,
		fileHashes:     make(map[string]string),
	}
}

// Watch starts watching for secret file changes and returns a channel of events.
func (w *SecretsWatcher) Watch(ctx context.Context) (<-chan event.Event, error) {
	watcher, err := fsnotify.NewWatcher()
	if err != nil {
		return nil, err
	}

	out := make(chan event.Event)

	go func() {
		defer close(out)
		defer watcher.Close()

		w.logger.Info("starting secrets watcher", "paths", w.watchPaths)

		// Add watch paths and scan for existing secrets
		for _, path := range w.watchPaths {
			if err := w.addWatchRecursive(watcher, path); err != nil {
				w.logger.Error("failed to add watch path", "path", path, "error", err)
			}
		}

		// Initial scan to hash existing secret files
		w.scanExistingSecrets()

		for {
			select {
			case <-ctx.Done():
				w.logger.Info("secrets watcher stopped", "reason", ctx.Err())
				return

			case evt, ok := <-watcher.Events:
				if !ok {
					return
				}

				// Check if this is a secret file
				if !w.isSecretFile(evt.Name) {
					continue
				}

				// Handle the event
				if e := w.handleEvent(evt); e != nil {
					select {
					case <-ctx.Done():
						return
					case out <- *e:
					}
				}

				// Add new directories to watch
				if evt.Has(fsnotify.Create) {
					if info, err := os.Stat(evt.Name); err == nil && info.IsDir() {
						_ = w.addWatchRecursive(watcher, evt.Name)
					}
				}

			case err, ok := <-watcher.Errors:
				if !ok {
					return
				}
				w.logger.Error("secrets watcher error", "error", err)
			}
		}
	}()

	return out, nil
}

// Name returns the watcher name.
func (w *SecretsWatcher) Name() string {
	return "secrets"
}

// addWatchRecursive adds a path and all subdirectories to the watcher.
func (w *SecretsWatcher) addWatchRecursive(watcher *fsnotify.Watcher, root string) error {
	return filepath.Walk(root, func(path string, info os.FileInfo, err error) error {
		if err != nil {
			return nil // Skip inaccessible paths
		}
		if info.IsDir() {
			if err := watcher.Add(path); err != nil {
				w.logger.Debug("failed to watch directory", "path", path, "error", err)
			}
		}
		return nil
	})
}

// isSecretFile checks if a file matches secret patterns.
func (w *SecretsWatcher) isSecretFile(path string) bool {
	filename := filepath.Base(path)

	for _, pattern := range w.secretPatterns {
		matched, err := filepath.Match(pattern, filename)
		if err == nil && matched {
			return true
		}
	}

	// Also check if file is in a secrets-related directory
	dir := filepath.Dir(path)
	dirName := filepath.Base(dir)
	secretDirs := []string{"secrets", ".secrets", "credentials", ".credentials", "certs", "ssl", "tls", ".ssh"}
	for _, sd := range secretDirs {
		if dirName == sd {
			return true
		}
	}

	return false
}

// scanExistingSecrets scans watch paths for existing secret files and hashes them.
func (w *SecretsWatcher) scanExistingSecrets() {
	for _, root := range w.watchPaths {
		filepath.Walk(root, func(path string, info os.FileInfo, err error) error {
			if err != nil || info.IsDir() {
				return nil
			}
			if w.isSecretFile(path) {
				if hash, err := w.hashFile(path); err == nil {
					w.mu.Lock()
					w.fileHashes[path] = hash
					w.mu.Unlock()
				}
			}
			return nil
		})
	}

	w.logger.Info("scanned existing secrets", "count", len(w.fileHashes))
}

// hashFile computes the SHA256 hash of a file.
func (w *SecretsWatcher) hashFile(path string) (string, error) {
	f, err := os.Open(path)
	if err != nil {
		return "", err
	}
	defer f.Close()

	h := sha256.New()
	if _, err := io.Copy(h, f); err != nil {
		return "", err
	}

	return hex.EncodeToString(h.Sum(nil)), nil
}

// handleEvent processes a filesystem event on a secret file.
func (w *SecretsWatcher) handleEvent(evt fsnotify.Event) *event.Event {
	filename := filepath.Base(evt.Name)
	dir := filepath.Dir(evt.Name)

	// Get file info if available
	var fileSize int64
	var fileMode string
	if info, err := os.Stat(evt.Name); err == nil {
		fileSize = info.Size()
		fileMode = info.Mode().String()
	}

	payload := map[string]any{
		"path":      evt.Name,
		"filename":  filename,
		"directory": dir,
	}

	if fileSize > 0 {
		payload["file_size"] = fileSize
	}
	if fileMode != "" {
		payload["file_mode"] = fileMode
	}

	var eventType event.EventType

	switch {
	case evt.Has(fsnotify.Create):
		eventType = event.SecretCreated
		payload["description"] = "New secret file created"

		// Hash the new file
		if hash, err := w.hashFile(evt.Name); err == nil {
			w.mu.Lock()
			w.fileHashes[evt.Name] = hash
			w.mu.Unlock()
		}

		w.logger.Info("secret file created",
			"path", evt.Name,
			"file", filename,
		)

	case evt.Has(fsnotify.Write):
		// Check if content actually changed (rotation detection)
		newHash, err := w.hashFile(evt.Name)
		if err != nil {
			return nil
		}

		w.mu.Lock()
		oldHash, existed := w.fileHashes[evt.Name]
		w.fileHashes[evt.Name] = newHash
		w.mu.Unlock()

		if existed && oldHash == newHash {
			// Content didn't actually change
			return nil
		}

		eventType = event.SecretRotated
		payload["description"] = "Secret file rotated (content changed)"
		payload["previous_hash"] = truncateHash(oldHash)
		payload["new_hash"] = truncateHash(newHash)

		w.logger.Info("secret rotated",
			"path", evt.Name,
			"file", filename,
		)

	case evt.Has(fsnotify.Remove) || evt.Has(fsnotify.Rename):
		eventType = event.SecretDeleted
		payload["description"] = "Secret file deleted or moved"

		w.mu.Lock()
		delete(w.fileHashes, evt.Name)
		w.mu.Unlock()

		w.logger.Info("secret file removed",
			"path", evt.Name,
			"file", filename,
		)

	case evt.Has(fsnotify.Chmod):
		eventType = event.SecretPermissionChanged
		payload["description"] = "Secret file permissions changed"

		w.logger.Info("secret permissions changed",
			"path", evt.Name,
			"file", filename,
			"mode", fileMode,
		)

	default:
		return nil
	}

	// Classify the secret type
	payload["secret_type"] = classifySecretType(filename, evt.Name)

	e := event.NewEvent(eventType, w.fortressID, w.serverID, payload)
	return &e
}

// classifySecretType attempts to identify what kind of secret this is.
func classifySecretType(filename, path string) string {
	lower := strings.ToLower(filename)
	lowerPath := strings.ToLower(path)

	switch {
	case strings.HasPrefix(lower, ".env"):
		return "environment_variables"
	case strings.HasSuffix(lower, ".pem") || strings.HasSuffix(lower, ".key") || strings.HasSuffix(lower, ".crt"):
		return "tls_certificate"
	case strings.HasPrefix(lower, "id_") || lower == "authorized_keys":
		return "ssh_key"
	case strings.Contains(lower, "credential"):
		return "credentials"
	case strings.Contains(lower, "token"):
		return "api_token"
	case strings.Contains(lower, "password") || lower == "passwd" || lower == "shadow":
		return "password"
	case strings.HasSuffix(lower, ".json") && (strings.Contains(lower, "service") || strings.Contains(lower, "account")):
		return "service_account"
	case strings.Contains(lowerPath, "/ssl/") || strings.Contains(lowerPath, "/tls/") || strings.Contains(lowerPath, "/certs/"):
		return "tls_certificate"
	case strings.Contains(lowerPath, "/.ssh/"):
		return "ssh_key"
	default:
		return "unknown"
	}
}

// truncateHash returns first 12 chars of a hash for display.
func truncateHash(hash string) string {
	if len(hash) > 12 {
		return hash[:12]
	}
	return hash
}
