# Rampart Agent Plugin System

The plugin system allows modular features to be added to the Rampart agent without modifying core code. Plugins can handle on-demand commands from the control plane and optionally provide passive monitoring.

## Architecture

```
Control Plane
     │
     ├── Commands (WebSocket/HTTP)
     │         │
     ▼         ▼
┌─────────────────────────┐
│     Plugin Registry     │
│  ┌───────────────────┐  │
│  │ command -> plugin │  │
│  └───────────────────┘  │
└─────────────────────────┘
         │
    ┌────┴────┬────────────┐
    ▼         ▼            ▼
┌────────┐ ┌────────┐ ┌────────┐
│pg_backup│ │ mysql  │ │ redis  │
│ plugin │ │ plugin │ │ plugin │
└────────┘ └────────┘ └────────┘
```

## Plugin Interface

Every plugin must implement the `Plugin` interface:

```go
type Plugin interface {
    // Unique identifier, e.g., "pg_backup"
    Name() string

    // Semantic version, e.g., "1.0.0"
    Version() string

    // Commands this plugin handles
    Commands() []string

    // Execute a command
    Execute(ctx context.Context, cmd Command, emit Emitter) error
}
```

### Optional: Passive Monitoring

Plugins that need to emit events periodically (not just in response to commands) can implement `WatcherPlugin`:

```go
type WatcherPlugin interface {
    Plugin
    Watch(ctx context.Context) (<-chan event.Event, error)
}
```

> **Note:** No plugins currently implement `WatcherPlugin`. Passive monitoring is handled by the watchers in `internal/watcher/` (docker, ssh, drift, etc.), which predate the plugin system.

## Creating a New Plugin

### 1. Create the Plugin Package

Create a new package under `internal/plugin/{name}/`:

```
internal/plugin/myfeature/
└── plugin.go
```

### 2. Implement the Plugin Interface

```go
package myfeature

import (
    "context"
    "encoding/json"
    "log/slog"

    "github.com/Tesseract-Systems-Corporation/rampart-agent/internal/plugin"
    "github.com/Tesseract-Systems-Corporation/rampart-agent/pkg/event"
)

type Plugin struct {
    logger *slog.Logger
}

func New(logger *slog.Logger) *Plugin {
    return &Plugin{
        logger: logger.With("plugin", "myfeature"),
    }
}

func (p *Plugin) Name() string    { return "myfeature" }
func (p *Plugin) Version() string { return "1.0.0" }

func (p *Plugin) Commands() []string {
    return []string{"trigger_myfeature", "myfeature_status"}
}

func (p *Plugin) Execute(ctx context.Context, cmd plugin.Command, emit plugin.Emitter) error {
    switch cmd.Type {
    case "trigger_myfeature":
        return p.handleTrigger(ctx, cmd, emit)
    case "myfeature_status":
        return p.handleStatus(ctx, cmd, emit)
    default:
        return nil
    }
}

func (p *Plugin) handleTrigger(ctx context.Context, cmd plugin.Command, emit plugin.Emitter) error {
    // Parse payload
    var payload struct {
        TargetID string `json:"target_id"`
    }
    if err := json.Unmarshal(cmd.Payload, &payload); err != nil {
        return err
    }

    // Do work...

    // Send result event
    ev := event.NewEvent("myfeature.completed", "", "", map[string]any{
        "target_id": payload.TargetID,
        "status":    "success",
    })
    return emit.SendImmediate(ctx, ev)
}
```

### 3. Register the Plugin

In `cmd/agent/main.go`, register your plugin:

```go
import "github.com/Tesseract-Systems-Corporation/rampart-agent/internal/plugin/myfeature"

// In run():
registry := plugin.NewRegistry(logger)
registry.Register(myfeature.New(logger))
```

## Command Naming Convention

Use descriptive command names that indicate the action:

- `trigger_{plugin}` - Start an on-demand operation
- `test_{plugin}_connection` - Test connectivity
- `{plugin}_status` - Get current status

## Event Naming Convention

Use namespaced event types:

- `{plugin}.started` - Operation began
- `{plugin}.progress` - Progress update
- `{plugin}.completed` - Operation succeeded
- `{plugin}.failed` - Operation failed

## Existing Plugins

### pg_backup

PostgreSQL backup plugin supporting local and S3 storage.

**Commands:**
- `trigger_pg_backup` - Start a backup job (single database or all databases)
- `test_pg_connection` - Test database connectivity

**Events:**
- `pg_backup.progress` - Real-time backup progress (includes multi-database status)
- `pg_connection.test_result` - Connection test result

**Features:**
- Single database or all-databases mode
- Gzip compression
- S3/object storage upload
- Partial success (continues if some databases fail)

### s3_storage

S3-compatible storage configuration plugin. Provides storage location management for backup destinations.

**Commands:**
- `test_s3_connection` - Test S3 bucket connectivity and permissions

**Events:**
- `s3_connection.test_result` - Connection test result with detailed permission checks

## Testing Plugins

Plugins can be tested in isolation by mocking the `Emitter` interface:

```go
type mockEmitter struct {
    events []event.Event
}

func (m *mockEmitter) Send(ev event.Event) {
    m.events = append(m.events, ev)
}

func (m *mockEmitter) SendImmediate(ctx context.Context, ev event.Event) error {
    m.events = append(m.events, ev)
    return nil
}

func TestPlugin(t *testing.T) {
    emit := &mockEmitter{}
    p := myfeature.New(slog.Default())

    cmd := plugin.Command{
        ID:      "test-cmd-1",
        Type:    "trigger_myfeature",
        Payload: json.RawMessage(`{"target_id": "test"}`),
    }

    err := p.Execute(context.Background(), cmd, emit)
    require.NoError(t, err)
    require.Len(t, emit.events, 1)
}
```
