package operations

import (
	"context"
	"log/slog"

	"github.com/Tesseract-Systems-Corporation/rampart-agent/internal/plugin"
)

// Operation is a single step type that can be executed.
type Operation interface {
	// Execute runs the operation with the given step config and context.
	Execute(ctx context.Context, step *plugin.Step, execCtx *ExecContext) error
}

// ExecContext holds the execution context for a workflow.
type ExecContext struct {
	// Plugin name
	PluginName string

	// Command being executed
	CommandName string

	// Config from the plugin instance (e.g., database credentials)
	Config map[string]interface{}

	// Storage configuration
	Storage map[string]interface{}

	// Job metadata
	JobID string

	// Temporary directory for this execution
	TempDir string

	// Variables set by previous steps
	Variables map[string]interface{}

	// Logger for this execution
	Logger *slog.Logger

	// Emitter for sending events
	Emitter plugin.Emitter

	// FortressID and ServerID for event routing
	FortressID string
	ServerID   string
}
