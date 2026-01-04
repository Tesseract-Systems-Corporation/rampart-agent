//go:build !linux

package watcher

import (
	"context"
	"errors"
	"log/slog"

	"github.com/Tesseract-Systems-Corporation/rampart-agent/pkg/event"
)

// EBPFWatcher is not supported on non-Linux systems
type EBPFWatcher struct{}

// EBPFWatcherConfig holds configuration for the eBPF watcher
type EBPFWatcherConfig struct {
	Enabled bool `yaml:"enabled"`
}

// NewEBPFWatcher returns an error on non-Linux systems
func NewEBPFWatcher(logger *slog.Logger, fortressID, serverID, controlPlaneHost string) (*EBPFWatcher, error) {
	return nil, errors.New("eBPF is only supported on Linux")
}

// Name returns the watcher name
func (w *EBPFWatcher) Name() string {
	return "ebpf"
}

// Watch is not implemented on non-Linux systems
func (w *EBPFWatcher) Watch(ctx context.Context) (<-chan event.Event, error) {
	return nil, errors.New("eBPF is only supported on Linux")
}

// RegisterContainerPID is a no-op on non-Linux systems
func (w *EBPFWatcher) RegisterContainerPID(pid uint32, info ContainerInfo) {}

// UnregisterContainerPID is a no-op on non-Linux systems
func (w *EBPFWatcher) UnregisterContainerPID(pid uint32) {}

// Close is a no-op on non-Linux systems
func (w *EBPFWatcher) Close() error {
	return nil
}

// IsEBPFSupported returns false on non-Linux systems
func IsEBPFSupported() bool {
	return false
}
