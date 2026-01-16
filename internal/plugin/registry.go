package plugin

import (
	"context"
	"errors"
	"fmt"
	"log/slog"
	"sync"

	"github.com/Tesseract-Systems-Corporation/rampart-agent/pkg/event"
)

// Common errors returned by the registry.
var (
	ErrUnknownCommand   = errors.New("unknown command")
	ErrPluginExists     = errors.New("plugin already registered")
	ErrCommandConflict  = errors.New("command already registered by another plugin")
)

// Registry manages plugins and routes commands to them.
type Registry struct {
	mu       sync.RWMutex
	plugins  map[string]Plugin // name -> plugin
	commands map[string]Plugin // command type -> plugin
	logger   *slog.Logger
}

// NewRegistry creates a new plugin registry.
func NewRegistry(logger *slog.Logger) *Registry {
	return &Registry{
		plugins:  make(map[string]Plugin),
		commands: make(map[string]Plugin),
		logger:   logger.With("component", "plugin-registry"),
	}
}

// Register adds a plugin to the registry.
// Returns an error if the plugin name is already registered or if any of its
// commands conflict with existing plugins.
func (r *Registry) Register(p Plugin) error {
	r.mu.Lock()
	defer r.mu.Unlock()

	name := p.Name()

	// Check if plugin already exists
	if _, exists := r.plugins[name]; exists {
		return fmt.Errorf("%w: %s", ErrPluginExists, name)
	}

	// Check for command conflicts
	for _, cmd := range p.Commands() {
		if existing, exists := r.commands[cmd]; exists {
			return fmt.Errorf("%w: command %q already registered by plugin %q",
				ErrCommandConflict, cmd, existing.Name())
		}
	}

	// Register the plugin and its commands
	r.plugins[name] = p
	for _, cmd := range p.Commands() {
		r.commands[cmd] = p
	}

	r.logger.Info("registered plugin",
		"name", name,
		"version", p.Version(),
		"commands", p.Commands(),
	)

	return nil
}

// HandleCommand routes a command to the appropriate plugin.
// Returns ErrUnknownCommand if no plugin handles this command type.
func (r *Registry) HandleCommand(ctx context.Context, cmd Command, emit Emitter) error {
	r.mu.RLock()
	plugin, exists := r.commands[cmd.Type]
	r.mu.RUnlock()

	if !exists {
		return fmt.Errorf("%w: %s", ErrUnknownCommand, cmd.Type)
	}

	r.logger.Debug("routing command to plugin",
		"command", cmd.Type,
		"command_id", cmd.ID,
		"plugin", plugin.Name(),
	)

	return plugin.Execute(ctx, cmd, emit)
}

// HasCommand returns true if any plugin handles the given command type.
func (r *Registry) HasCommand(cmdType string) bool {
	r.mu.RLock()
	defer r.mu.RUnlock()
	_, exists := r.commands[cmdType]
	return exists
}

// GetPlugin returns a plugin by name, or nil if not found.
func (r *Registry) GetPlugin(name string) Plugin {
	r.mu.RLock()
	defer r.mu.RUnlock()
	return r.plugins[name]
}

// Plugins returns all registered plugins.
func (r *Registry) Plugins() []Plugin {
	r.mu.RLock()
	defer r.mu.RUnlock()

	result := make([]Plugin, 0, len(r.plugins))
	for _, p := range r.plugins {
		result = append(result, p)
	}
	return result
}

// WatcherPlugins returns all plugins that implement WatcherPlugin.
func (r *Registry) WatcherPlugins() []WatcherPlugin {
	r.mu.RLock()
	defer r.mu.RUnlock()

	var result []WatcherPlugin
	for _, p := range r.plugins {
		if wp, ok := p.(WatcherPlugin); ok {
			result = append(result, wp)
		}
	}
	return result
}

// watcherAdapter wraps a WatcherPlugin to implement the watcher.Watcher interface.
type watcherAdapter struct {
	plugin WatcherPlugin
}

func (w *watcherAdapter) Name() string {
	return w.plugin.Name()
}

func (w *watcherAdapter) Watch(ctx context.Context) (<-chan event.Event, error) {
	return w.plugin.Watch(ctx)
}

// Watcher is the interface that watcher.Watcher implements.
// We define it here to avoid a circular import with the watcher package.
type Watcher interface {
	Watch(ctx context.Context) (<-chan event.Event, error)
	Name() string
}

// GetWatchers returns all WatcherPlugins wrapped as Watchers.
// This allows them to be used with the existing Multiplexer.
func (r *Registry) GetWatchers() []Watcher {
	r.mu.RLock()
	defer r.mu.RUnlock()

	var result []Watcher
	for _, p := range r.plugins {
		if wp, ok := p.(WatcherPlugin); ok {
			result = append(result, &watcherAdapter{plugin: wp})
		}
	}
	return result
}
