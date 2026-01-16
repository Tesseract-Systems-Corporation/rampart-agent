// Package updater provides self-update functionality for the Rampart agent.
package updater

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"log/slog"
	"net/http"
	"os"
	"runtime"
	"strings"
	"time"
)

const (
	githubRepo    = "Tesseract-Systems-Corporation/rampart-agent"
	binaryPrefix  = "rampart-agent"
	updateTimeout = 5 * time.Minute
)

// UpdateResult contains the result of an update operation.
type UpdateResult struct {
	Success        bool   `json:"success"`
	PreviousVersion string `json:"previous_version"`
	NewVersion     string `json:"new_version"`
	Error          string `json:"error,omitempty"`
	RestartRequired bool   `json:"restart_required"`
}

// Updater handles self-update operations.
type Updater struct {
	logger         *slog.Logger
	currentVersion string
}

// New creates a new Updater.
func New(logger *slog.Logger, currentVersion string) *Updater {
	return &Updater{
		logger:         logger.With("component", "updater"),
		currentVersion: currentVersion,
	}
}

// GetLatestVersion fetches the latest release version from GitHub.
func (u *Updater) GetLatestVersion(ctx context.Context) (string, error) {
	url := fmt.Sprintf("https://api.github.com/repos/%s/releases/latest", githubRepo)

	req, err := http.NewRequestWithContext(ctx, "GET", url, nil)
	if err != nil {
		return "", fmt.Errorf("create request: %w", err)
	}
	req.Header.Set("Accept", "application/vnd.github.v3+json")

	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		return "", fmt.Errorf("fetch latest release: %w", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		return "", fmt.Errorf("github API returned status %d", resp.StatusCode)
	}

	var release struct {
		TagName string `json:"tag_name"`
	}
	if err := json.NewDecoder(resp.Body).Decode(&release); err != nil {
		return "", fmt.Errorf("decode response: %w", err)
	}

	return release.TagName, nil
}

// Update downloads and installs a new version of the agent.
// If version is empty or "latest", it fetches the latest release.
// Returns UpdateResult with details about the operation.
func (u *Updater) Update(ctx context.Context, version string) UpdateResult {
	result := UpdateResult{
		PreviousVersion: u.currentVersion,
	}

	// Create context with timeout
	ctx, cancel := context.WithTimeout(ctx, updateTimeout)
	defer cancel()

	// Resolve version
	if version == "" || version == "latest" {
		u.logger.Info("fetching latest version")
		latest, err := u.GetLatestVersion(ctx)
		if err != nil {
			result.Error = fmt.Sprintf("failed to get latest version: %v", err)
			u.logger.Error("failed to get latest version", "error", err)
			return result
		}
		version = latest
	}

	// Normalize version (ensure it starts with 'v')
	if !strings.HasPrefix(version, "v") {
		version = "v" + version
	}

	result.NewVersion = version

	// Check if already on this version
	if version == u.currentVersion {
		result.Success = true
		result.Error = "already running requested version"
		u.logger.Info("already running requested version", "version", version)
		return result
	}

	u.logger.Info("starting update", "from", u.currentVersion, "to", version)

	// Determine binary name for this platform
	binaryName := fmt.Sprintf("%s-%s-%s", binaryPrefix, runtime.GOOS, runtime.GOARCH)
	downloadURL := fmt.Sprintf("https://github.com/%s/releases/download/%s/%s",
		githubRepo, version, binaryName)

	u.logger.Info("downloading binary", "url", downloadURL)

	// Download binary to temp file
	tmpFile, err := u.downloadBinary(ctx, downloadURL)
	if err != nil {
		result.Error = fmt.Sprintf("failed to download binary: %v", err)
		u.logger.Error("failed to download binary", "error", err)
		return result
	}
	defer os.Remove(tmpFile) // Clean up on failure

	// Get current executable path
	execPath, err := os.Executable()
	if err != nil {
		result.Error = fmt.Sprintf("failed to get executable path: %v", err)
		u.logger.Error("failed to get executable path", "error", err)
		return result
	}

	u.logger.Info("replacing binary", "path", execPath)

	// Replace the binary
	if err := u.replaceBinary(tmpFile, execPath); err != nil {
		result.Error = fmt.Sprintf("failed to replace binary: %v", err)
		u.logger.Error("failed to replace binary", "error", err)
		return result
	}

	result.Success = true
	result.RestartRequired = true

	u.logger.Info("update completed successfully",
		"from", u.currentVersion,
		"to", version,
	)

	return result
}

// downloadBinary downloads a binary from the given URL to a temp file.
// Returns the temp file path.
func (u *Updater) downloadBinary(ctx context.Context, url string) (string, error) {
	req, err := http.NewRequestWithContext(ctx, "GET", url, nil)
	if err != nil {
		return "", fmt.Errorf("create request: %w", err)
	}

	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		return "", fmt.Errorf("download: %w", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		return "", fmt.Errorf("download failed with status %d", resp.StatusCode)
	}

	// Create temp file
	tmpFile, err := os.CreateTemp("", "rampart-agent-update-*")
	if err != nil {
		return "", fmt.Errorf("create temp file: %w", err)
	}
	tmpPath := tmpFile.Name()

	// Copy download to temp file
	written, err := io.Copy(tmpFile, resp.Body)
	if err != nil {
		tmpFile.Close()
		os.Remove(tmpPath)
		return "", fmt.Errorf("write temp file: %w", err)
	}
	tmpFile.Close()

	u.logger.Info("downloaded binary", "size", written, "path", tmpPath)

	// Make executable
	if err := os.Chmod(tmpPath, 0755); err != nil {
		os.Remove(tmpPath)
		return "", fmt.Errorf("chmod: %w", err)
	}

	return tmpPath, nil
}

// replaceBinary atomically replaces the current binary with the new one.
func (u *Updater) replaceBinary(newPath, targetPath string) error {
	// Get permissions from existing binary
	info, err := os.Stat(targetPath)
	if err != nil {
		return fmt.Errorf("stat existing binary: %w", err)
	}

	// On Linux, we can't replace a running binary directly.
	// Instead, we rename the old one and move the new one in place.
	backupPath := targetPath + ".old"

	// Remove any existing backup
	os.Remove(backupPath)

	// Rename current binary to backup
	if err := os.Rename(targetPath, backupPath); err != nil {
		return fmt.Errorf("backup current binary: %w", err)
	}

	// Move new binary into place
	if err := os.Rename(newPath, targetPath); err != nil {
		// Try to restore backup
		os.Rename(backupPath, targetPath)
		return fmt.Errorf("install new binary: %w", err)
	}

	// Set same permissions as original
	if err := os.Chmod(targetPath, info.Mode()); err != nil {
		u.logger.Warn("failed to set permissions on new binary", "error", err)
	}

	// Remove backup (best effort)
	os.Remove(backupPath)

	return nil
}
