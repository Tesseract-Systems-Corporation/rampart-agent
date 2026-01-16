// Package s3storage provides S3-compatible storage management for backups.
package s3storage

import (
	"context"
	_ "embed"
	"log/slog"

	"github.com/Tesseract-Systems-Corporation/rampart-agent/internal/plugin"
)

//go:embed manifest.yaml
var manifestYAML []byte

// Plugin implements the S3 storage plugin.
type Plugin struct {
	manifest *plugin.Manifest
	logger   *slog.Logger
}

// New creates a new S3 storage plugin instance.
func New(logger *slog.Logger) (*Plugin, error) {
	manifest, err := plugin.ParseManifest(manifestYAML)
	if err != nil {
		return nil, err
	}

	return &Plugin{
		manifest: manifest,
		logger:   logger.With("plugin", "s3_storage"),
	}, nil
}

// Name returns the plugin name.
func (p *Plugin) Name() string {
	return p.manifest.Metadata.Name
}

// Version returns the plugin version.
func (p *Plugin) Version() string {
	return p.manifest.Metadata.Version
}

// Commands returns the list of commands this plugin handles.
func (p *Plugin) Commands() []string {
	return p.manifest.CommandNames()
}

// Manifest returns the plugin manifest.
func (p *Plugin) Manifest() *plugin.Manifest {
	return p.manifest
}

// Execute handles a command from the control plane.
// S3 storage commands are typically handled by the control plane directly,
// since the agent doesn't need to interact with S3 for configuration.
func (p *Plugin) Execute(ctx context.Context, cmd plugin.Command, emit plugin.Emitter) error {
	switch cmd.Type {
	case "test_s3_connection":
		// S3 tests are done from control plane - this is a no-op on agent side
		p.logger.Info("s3 connection test - handled by control plane")
		return nil
	default:
		p.logger.Warn("unknown command", "command", cmd.Type)
		return nil
	}
}
