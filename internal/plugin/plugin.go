// Package plugin provides a modular plugin system for the Rampart agent.
//
// Plugins can handle on-demand commands from the control plane and optionally
// provide passive monitoring through the Watcher interface.
package plugin

import (
	"context"
	"encoding/json"

	"github.com/Tesseract-Systems-Corporation/rampart-agent/pkg/event"
)

// Plugin is the core interface that all plugins must implement.
type Plugin interface {
	// Name returns the unique identifier for this plugin.
	// Examples: "pg_backup", "mysql_backup", "redis_backup"
	Name() string

	// Version returns the semantic version of this plugin.
	// Example: "1.0.0"
	Version() string

	// Commands returns the list of command types this plugin handles.
	// Examples: ["trigger_pg_backup", "test_pg_connection"]
	Commands() []string

	// Execute handles a command from the control plane.
	// The plugin should send events back via the emitter.
	// This method is called in a goroutine - it can block.
	Execute(ctx context.Context, cmd Command, emit Emitter) error

	// Manifest returns the plugin's manifest, which contains metadata,
	// configuration schema, and capability declarations.
	// Returns nil for plugins that don't have a manifest.
	Manifest() *Manifest
}

// WatcherPlugin extends Plugin with passive monitoring capabilities.
// Plugins that need to emit events periodically (not just in response to
// commands) should implement this interface.
type WatcherPlugin interface {
	Plugin

	// Watch starts passive monitoring and returns a channel of events.
	// The channel should be closed when the context is cancelled.
	Watch(ctx context.Context) (<-chan event.Event, error)
}

// Command represents a command from the control plane.
type Command struct {
	// ID is the unique identifier for this command instance.
	ID string

	// Type is the command type, e.g., "trigger_pg_backup".
	Type string

	// Payload contains command-specific parameters as JSON.
	Payload json.RawMessage
}

// Emitter is the interface for sending events back to the control plane.
// This abstracts the emitter implementation so plugins don't depend on it directly.
type Emitter interface {
	// Send queues an event for batched delivery.
	Send(ev event.Event)

	// SendImmediate sends an event immediately (for real-time updates).
	SendImmediate(ctx context.Context, ev event.Event) error
}
