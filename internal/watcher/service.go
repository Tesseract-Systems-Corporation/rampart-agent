package watcher

import (
	"bufio"
	"context"
	"log/slog"
	"os/exec"
	"runtime"
	"strings"
	"time"

	"github.com/Tesseract-Systems-Corporation/rampart-agent/pkg/event"
)

// DefaultServicePollInterval is the default interval for polling systemd service states.
const DefaultServicePollInterval = 60 * time.Second

// ServiceConfig holds configuration for the Service watcher.
type ServiceConfig struct {
	// PollInterval is how often to poll systemctl for service states.
	// Defaults to DefaultServicePollInterval if zero.
	PollInterval time.Duration

	// FortressID is the ID of the Fortress this agent belongs to.
	FortressID string

	// ServerID is the ID of this server.
	ServerID string

	// Logger is the logger to use. If nil, uses slog.Default().
	Logger *slog.Logger
}

// ServiceState represents the state of a systemd service.
type ServiceState struct {
	Name        string
	LoadState   string // loaded, not-found, masked
	ActiveState string // active, inactive, failed, activating, deactivating
	SubState    string // running, exited, dead, failed, etc.
	UnitFile    string // enabled, disabled, static, masked
}

// ServiceWatcher monitors systemd service state changes.
type ServiceWatcher struct {
	pollInterval time.Duration
	fortressID   string
	serverID     string
	logger       *slog.Logger
	lastStates   map[string]ServiceState

	// commandRunner allows injecting a mock for testing
	commandRunner func(name string, args ...string) ([]byte, error)
}

// NewServiceWatcher creates a new ServiceWatcher with the given configuration.
func NewServiceWatcher(cfg ServiceConfig) *ServiceWatcher {
	interval := cfg.PollInterval
	if interval == 0 {
		interval = DefaultServicePollInterval
	}

	logger := cfg.Logger
	if logger == nil {
		logger = slog.Default()
	}

	return &ServiceWatcher{
		pollInterval:  interval,
		fortressID:    cfg.FortressID,
		serverID:      cfg.ServerID,
		logger:        logger,
		lastStates:    make(map[string]ServiceState),
		commandRunner: defaultCommandRunner,
	}
}

// defaultCommandRunner executes a command and returns its output.
func defaultCommandRunner(name string, args ...string) ([]byte, error) {
	return exec.Command(name, args...).Output()
}

// Watch starts watching systemd service states and returns a channel of events.
func (w *ServiceWatcher) Watch(ctx context.Context) (<-chan event.Event, error) {
	out := make(chan event.Event)

	go func() {
		defer close(out)

		// Skip on non-Linux systems
		if runtime.GOOS != "linux" {
			w.logger.Info("service watcher skipped on non-linux system", "os", runtime.GOOS)
			<-ctx.Done()
			return
		}

		w.logger.Info("starting service watcher", "interval", w.pollInterval)

		// Initial poll to establish baseline
		w.pollServices(ctx, out, true)

		ticker := time.NewTicker(w.pollInterval)
		defer ticker.Stop()

		for {
			select {
			case <-ctx.Done():
				w.logger.Info("service watcher stopped", "reason", ctx.Err())
				return
			case <-ticker.C:
				w.pollServices(ctx, out, false)
			}
		}
	}()

	return out, nil
}

// Name returns the watcher name.
func (w *ServiceWatcher) Name() string {
	return "service"
}

// pollServices polls systemctl for current service states and emits events for changes.
func (w *ServiceWatcher) pollServices(ctx context.Context, out chan<- event.Event, initial bool) {
	states, err := w.getServiceStates()
	if err != nil {
		w.logger.Error("failed to get service states", "error", err)
		return
	}

	// On initial poll, just record the baseline
	if initial {
		w.lastStates = states
		w.logger.Debug("service watcher baseline established", "services", len(states))
		return
	}

	// Compare with previous states and emit events
	for name, current := range states {
		previous, existed := w.lastStates[name]

		if !existed {
			// New service detected
			e := w.createServiceEvent(event.ServiceCreated, name, "", current.ActiveState, current.UnitFile)
			w.sendEvent(ctx, out, e)
			continue
		}

		// Check for state changes
		if previous.ActiveState != current.ActiveState {
			eventType := w.getStateChangeEventType(previous.ActiveState, current.ActiveState)
			if eventType != "" {
				e := w.createServiceEvent(eventType, name, previous.ActiveState, current.ActiveState, current.UnitFile)
				w.sendEvent(ctx, out, e)
			}
		}

		// Check for enable/disable changes
		if previous.UnitFile != current.UnitFile {
			eventType := w.getEnableChangeEventType(previous.UnitFile, current.UnitFile)
			if eventType != "" {
				e := w.createServiceEvent(eventType, name, previous.UnitFile, current.UnitFile, current.UnitFile)
				w.sendEvent(ctx, out, e)
			}
		}
	}

	// Check for deleted services
	for name, previous := range w.lastStates {
		if _, exists := states[name]; !exists {
			e := w.createServiceEvent(event.ServiceDeleted, name, previous.ActiveState, "deleted", previous.UnitFile)
			w.sendEvent(ctx, out, e)
		}
	}

	w.lastStates = states
}

// getServiceStates runs systemctl and parses the output.
func (w *ServiceWatcher) getServiceStates() (map[string]ServiceState, error) {
	// systemctl list-units --type=service --all --no-legend --no-pager
	// Output format: UNIT LOAD ACTIVE SUB DESCRIPTION
	output, err := w.commandRunner("systemctl", "list-units", "--type=service", "--all", "--no-legend", "--no-pager")
	if err != nil {
		return nil, err
	}

	states := parseSystemctlOutput(string(output))

	// Also get unit file states (enabled/disabled)
	unitOutput, err := w.commandRunner("systemctl", "list-unit-files", "--type=service", "--no-legend", "--no-pager")
	if err != nil {
		w.logger.Debug("failed to get unit file states", "error", err)
	} else {
		unitStates := parseUnitFileOutput(string(unitOutput))
		for name, unitState := range unitStates {
			if state, exists := states[name]; exists {
				state.UnitFile = unitState
				states[name] = state
			} else {
				// Service not loaded but has a unit file
				states[name] = ServiceState{
					Name:        name,
					LoadState:   "not-found",
					ActiveState: "inactive",
					SubState:    "dead",
					UnitFile:    unitState,
				}
			}
		}
	}

	return states, nil
}

// parseSystemctlOutput parses the output of systemctl list-units.
func parseSystemctlOutput(output string) map[string]ServiceState {
	states := make(map[string]ServiceState)

	scanner := bufio.NewScanner(strings.NewReader(output))
	for scanner.Scan() {
		line := strings.TrimSpace(scanner.Text())
		if line == "" {
			continue
		}

		state := parseServiceLine(line)
		if state.Name != "" {
			states[state.Name] = state
		}
	}

	return states
}

// parseServiceLine parses a single line from systemctl list-units output.
// Format: UNIT LOAD ACTIVE SUB DESCRIPTION...
func parseServiceLine(line string) ServiceState {
	fields := strings.Fields(line)
	if len(fields) < 4 {
		return ServiceState{}
	}

	name := fields[0]
	// Strip .service suffix for cleaner names
	name = strings.TrimSuffix(name, ".service")

	return ServiceState{
		Name:        name,
		LoadState:   fields[1],
		ActiveState: fields[2],
		SubState:    fields[3],
	}
}

// parseUnitFileOutput parses the output of systemctl list-unit-files.
// Format: UNIT STATE VENDOR PRESET
func parseUnitFileOutput(output string) map[string]string {
	states := make(map[string]string)

	scanner := bufio.NewScanner(strings.NewReader(output))
	for scanner.Scan() {
		line := strings.TrimSpace(scanner.Text())
		if line == "" {
			continue
		}

		fields := strings.Fields(line)
		if len(fields) < 2 {
			continue
		}

		name := fields[0]
		name = strings.TrimSuffix(name, ".service")
		state := fields[1]

		states[name] = state
	}

	return states
}

// getStateChangeEventType returns the appropriate event type for a state change.
func (w *ServiceWatcher) getStateChangeEventType(previous, current string) event.EventType {
	// Determine if service started or stopped
	switch current {
	case "active":
		if previous != "active" {
			return event.ServiceStarted
		}
	case "inactive", "failed", "deactivating":
		if previous == "active" || previous == "activating" {
			return event.ServiceStopped
		}
	}
	return ""
}

// getEnableChangeEventType returns the appropriate event type for an enable/disable change.
func (w *ServiceWatcher) getEnableChangeEventType(previous, current string) event.EventType {
	switch {
	case current == "enabled" && previous != "enabled":
		return event.ServiceEnabled
	case (current == "disabled" || current == "masked") && previous == "enabled":
		return event.ServiceDisabled
	}
	return ""
}

// createServiceEvent creates a new service event.
func (w *ServiceWatcher) createServiceEvent(eventType event.EventType, serviceName, previousState, newState, unitFile string) event.Event {
	payload := map[string]any{
		"service_name": serviceName,
		"new_state":    newState,
		"init_system":  "systemd",
	}

	if previousState != "" {
		payload["previous_state"] = previousState
	}

	if unitFile != "" {
		payload["unit_file"] = unitFile
	}

	return event.NewEvent(eventType, w.fortressID, w.serverID, payload)
}

// sendEvent sends an event on the channel, respecting context cancellation.
func (w *ServiceWatcher) sendEvent(ctx context.Context, out chan<- event.Event, e event.Event) {
	w.logger.Debug("service event",
		"type", e.Type,
		"service", e.Payload["service_name"],
		"state", e.Payload["new_state"],
	)

	select {
	case <-ctx.Done():
	case out <- e:
	}
}
