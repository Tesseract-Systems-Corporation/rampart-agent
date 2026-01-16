// Package declarative provides execution of YAML-defined plugin workflows.
package declarative

import (
	"context"
	"fmt"
	"log/slog"
	"os"

	"github.com/Tesseract-Systems-Corporation/rampart-agent/internal/plugin"
	"github.com/Tesseract-Systems-Corporation/rampart-agent/internal/plugin/declarative/operations"
	"github.com/Tesseract-Systems-Corporation/rampart-agent/pkg/event"
)

// Executor runs declarative plugin workflows.
type Executor struct {
	logger  *slog.Logger
	emitter plugin.Emitter
	ops     map[string]operations.Operation
}

// NewExecutor creates a new declarative workflow executor.
func NewExecutor(logger *slog.Logger) *Executor {
	e := &Executor{
		logger: logger.With("component", "declarative-executor"),
		ops:    make(map[string]operations.Operation),
	}

	// Register built-in operations
	e.RegisterOperation("exec", &operations.ExecOperation{})
	e.RegisterOperation("compress", &operations.CompressOperation{})
	e.RegisterOperation("upload", &operations.UploadOperation{})
	// TODO: Add more operations as needed
	// e.RegisterOperation("http", &operations.HTTPOperation{})
	// e.RegisterOperation("file.read", &operations.FileReadOperation{})
	// e.RegisterOperation("file.write", &operations.FileWriteOperation{})

	return e
}

// RegisterOperation registers a custom operation type.
func (e *Executor) RegisterOperation(name string, op operations.Operation) {
	e.ops[name] = op
}

// ExecuteWorkflow runs a declarative workflow.
func (e *Executor) ExecuteWorkflow(
	ctx context.Context,
	manifest *plugin.Manifest,
	commandName string,
	config map[string]interface{},
	storage map[string]interface{},
	jobID string,
	emitter plugin.Emitter,
	fortressID, serverID string,
) error {
	workflow := manifest.GetWorkflow(commandName)
	if workflow == nil {
		return fmt.Errorf("no workflow defined for command %q", commandName)
	}

	// Create temp directory for this execution
	tempDir, err := os.MkdirTemp("", fmt.Sprintf("rampart-%s-", manifest.Metadata.Name))
	if err != nil {
		return fmt.Errorf("create temp dir: %w", err)
	}
	defer os.RemoveAll(tempDir)

	// Create execution context
	execCtx := &operations.ExecContext{
		PluginName:  manifest.Metadata.Name,
		CommandName: commandName,
		Config:      config,
		Storage:     storage,
		JobID:       jobID,
		TempDir:     tempDir,
		Variables:   make(map[string]interface{}),
		Logger:      e.logger.With("plugin", manifest.Metadata.Name, "command", commandName, "job_id", jobID),
		Emitter:     emitter,
		FortressID:  fortressID,
		ServerID:    serverID,
	}

	// Execute each step in order
	for i, step := range workflow.Steps {
		stepLogger := execCtx.Logger.With("step", i, "type", step.Type)
		stepLogger.Info("executing step")

		op, ok := e.ops[step.Type]
		if !ok {
			return fmt.Errorf("unknown operation type %q in step %d", step.Type, i)
		}

		// Execute the step
		stepCopy := step // Copy to avoid modifying original
		if err := op.Execute(ctx, &stepCopy, execCtx); err != nil {
			stepLogger.Error("step failed", "error", err)

			// Handle onFailure if defined
			if step.OnFailure != nil && step.OnFailure.Emit != nil {
				e.emitEvent(ctx, step.OnFailure.Emit, execCtx, map[string]interface{}{
					"error": err.Error(),
				})
			}

			return fmt.Errorf("step %d (%s) failed: %w", i, step.Type, err)
		}

		// Handle onSuccess if defined
		if step.OnSuccess != nil && step.OnSuccess.Emit != nil {
			e.emitEvent(ctx, step.OnSuccess.Emit, execCtx, nil)
		}

		stepLogger.Info("step completed")
	}

	return nil
}

// emitEvent sends an event to the control plane.
func (e *Executor) emitEvent(ctx context.Context, emit *plugin.EmitAction, execCtx *operations.ExecContext, extraVars map[string]interface{}) {
	// Build template data
	data := e.buildTemplateData(execCtx)
	for k, v := range extraVars {
		data[k] = v
	}

	// Render event type
	eventType, err := RenderTemplate(emit.Type, data)
	if err != nil {
		execCtx.Logger.Warn("failed to render event type", "error", err)
		eventType = emit.Type
	}

	// Render payload values
	payload := make(map[string]interface{})
	for k, v := range emit.Payload {
		if s, ok := v.(string); ok {
			rendered, err := RenderTemplate(s, data)
			if err == nil {
				payload[k] = rendered
			} else {
				payload[k] = v
			}
		} else {
			payload[k] = v
		}
	}

	ev := event.NewEvent(event.EventType(eventType), execCtx.FortressID, execCtx.ServerID, payload)
	if err := execCtx.Emitter.SendImmediate(ctx, ev); err != nil {
		execCtx.Logger.Warn("failed to emit event", "type", eventType, "error", err)
	}
}

// buildTemplateData builds the data map for template rendering.
func (e *Executor) buildTemplateData(execCtx *operations.ExecContext) map[string]interface{} {
	return map[string]interface{}{
		"plugin":   execCtx.PluginName,
		"command":  execCtx.CommandName,
		"config":   execCtx.Config,
		"storage":  execCtx.Storage,
		"job_id":   execCtx.JobID,
		"tempdir":  execCtx.TempDir,
		"vars":     execCtx.Variables,
	}
}

