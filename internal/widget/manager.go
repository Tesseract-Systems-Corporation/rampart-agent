// Package widget provides widget enablement management for the agent.
package widget

import (
	"log/slog"
	"sync"
)

// Manager tracks enabled widgets and controls which watchers should run.
type Manager struct {
	enabledWidgets map[string]bool
	mu             sync.RWMutex
	logger         *slog.Logger
	onChange       func(widgetID string, enabled bool)
}

// NewManager creates a new widget manager.
func NewManager(logger *slog.Logger) *Manager {
	return &Manager{
		enabledWidgets: make(map[string]bool),
		logger:         logger,
	}
}

// SetOnChange sets a callback that fires when a widget's enabled state changes.
func (m *Manager) SetOnChange(fn func(widgetID string, enabled bool)) {
	m.onChange = fn
}

// UpdateEnabled updates the list of enabled widgets from the control plane.
// Returns lists of newly enabled and newly disabled widgets.
func (m *Manager) UpdateEnabled(widgets []string) (enabled, disabled []string) {
	m.mu.Lock()
	defer m.mu.Unlock()

	// Convert slice to map for O(1) lookup
	newEnabled := make(map[string]bool)
	for _, w := range widgets {
		newEnabled[w] = true
	}

	// Find newly disabled widgets
	for id := range m.enabledWidgets {
		if !newEnabled[id] {
			disabled = append(disabled, id)
			if m.onChange != nil {
				m.onChange(id, false)
			}
		}
	}

	// Find newly enabled widgets
	for id := range newEnabled {
		if !m.enabledWidgets[id] {
			enabled = append(enabled, id)
			if m.onChange != nil {
				m.onChange(id, true)
			}
		}
	}

	// Update state
	m.enabledWidgets = newEnabled

	if len(enabled) > 0 || len(disabled) > 0 {
		m.logger.Info("widget state updated",
			"enabled", enabled,
			"disabled", disabled,
		)
	}

	return enabled, disabled
}

// IsEnabled returns whether a widget is currently enabled.
func (m *Manager) IsEnabled(widgetID string) bool {
	m.mu.RLock()
	defer m.mu.RUnlock()
	return m.enabledWidgets[widgetID]
}

// GetEnabled returns a slice of all enabled widget IDs.
func (m *Manager) GetEnabled() []string {
	m.mu.RLock()
	defer m.mu.RUnlock()

	result := make([]string, 0, len(m.enabledWidgets))
	for id := range m.enabledWidgets {
		result = append(result, id)
	}
	return result
}
