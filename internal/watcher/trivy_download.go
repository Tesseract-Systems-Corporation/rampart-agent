package watcher

import (
	"archive/tar"
	"compress/gzip"
	"fmt"
	"io"
	"net/http"
	"os"
	"path/filepath"
	"runtime"
	"strings"
)

// TrivyVersion is the version of Trivy to download
const TrivyVersion = "0.58.0"

// TrivyInstallDir is where we install Trivy
const TrivyInstallDir = "/opt/rampart/bin"

// getTrivyDownloadURL returns the download URL for the current platform
func getTrivyDownloadURL() (string, error) {
	if runtime.GOOS != "linux" {
		return "", fmt.Errorf("trivy auto-download only supported on Linux (got %s)", runtime.GOOS)
	}

	var arch string
	switch runtime.GOARCH {
	case "amd64":
		arch = "64bit"
	case "arm64":
		arch = "ARM64"
	default:
		return "", fmt.Errorf("unsupported architecture: %s", runtime.GOARCH)
	}

	// Trivy release URL format
	url := fmt.Sprintf(
		"https://github.com/aquasecurity/trivy/releases/download/v%s/trivy_%s_Linux-%s.tar.gz",
		TrivyVersion, TrivyVersion, arch,
	)

	return url, nil
}

// EnsureTrivyInstalled checks if Trivy is installed and downloads it if not.
// Returns the path to the trivy binary.
func EnsureTrivyInstalled() (string, error) {
	// Check common locations first
	locations := []string{
		filepath.Join(TrivyInstallDir, "trivy"),
		"/usr/local/bin/trivy",
		"/usr/bin/trivy",
	}

	for _, path := range locations {
		if _, err := os.Stat(path); err == nil {
			return path, nil
		}
	}

	// Also check PATH
	if path, err := findInPath("trivy"); err == nil {
		return path, nil
	}

	// Not found, download it
	return downloadTrivy()
}

// findInPath looks for an executable in PATH
func findInPath(name string) (string, error) {
	pathEnv := os.Getenv("PATH")
	for _, dir := range strings.Split(pathEnv, ":") {
		path := filepath.Join(dir, name)
		if info, err := os.Stat(path); err == nil && !info.IsDir() {
			return path, nil
		}
	}
	return "", fmt.Errorf("%s not found in PATH", name)
}

// downloadTrivy downloads and installs Trivy
func downloadTrivy() (string, error) {
	url, err := getTrivyDownloadURL()
	if err != nil {
		return "", err
	}

	// Create install directory
	if err := os.MkdirAll(TrivyInstallDir, 0755); err != nil {
		return "", fmt.Errorf("create install dir: %w", err)
	}

	destPath := filepath.Join(TrivyInstallDir, "trivy")

	// Log that we're downloading (this will show in agent logs)
	fmt.Printf("rampart-agent: downloading trivy v%s...\n", TrivyVersion)

	// Download
	resp, err := http.Get(url)
	if err != nil {
		return "", fmt.Errorf("download trivy: %w", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		return "", fmt.Errorf("download trivy: HTTP %d", resp.StatusCode)
	}

	// Extract tar.gz
	gzr, err := gzip.NewReader(resp.Body)
	if err != nil {
		return "", fmt.Errorf("decompress: %w", err)
	}
	defer gzr.Close()

	tr := tar.NewReader(gzr)

	for {
		header, err := tr.Next()
		if err == io.EOF {
			break
		}
		if err != nil {
			return "", fmt.Errorf("read tar: %w", err)
		}

		// We only care about the trivy binary
		if header.Name == "trivy" && header.Typeflag == tar.TypeReg {
			outFile, err := os.OpenFile(destPath, os.O_CREATE|os.O_WRONLY|os.O_TRUNC, 0755)
			if err != nil {
				return "", fmt.Errorf("create binary: %w", err)
			}

			if _, err := io.Copy(outFile, tr); err != nil {
				outFile.Close()
				return "", fmt.Errorf("write binary: %w", err)
			}
			outFile.Close()

			fmt.Printf("rampart-agent: trivy installed to %s\n", destPath)
			return destPath, nil
		}
	}

	return "", fmt.Errorf("trivy binary not found in archive")
}

// GetTrivyPath returns the path to trivy, downloading if necessary.
// This is a convenience wrapper around EnsureTrivyInstalled.
func GetTrivyPath() string {
	path, err := EnsureTrivyInstalled()
	if err != nil {
		return "" // Will be handled by the caller
	}
	return path
}
