// Package operations provides declarative workflow step implementations.
package operations

import (
	"context"
	"fmt"
	"io"
	"os"
	"os/exec"
	"time"

	"github.com/Tesseract-Systems-Corporation/rampart-agent/internal/plugin"
)

// AllowedBinaries is the list of binaries that can be executed by declarative plugins.
// This is a security measure to prevent arbitrary code execution.
var AllowedBinaries = map[string]bool{
	// PostgreSQL
	"pg_dump":    true,
	"pg_dumpall": true,
	"psql":       true,
	"pg_restore": true,

	// MySQL
	"mysqldump": true,
	"mysql":     true,

	// MongoDB
	"mongodump":   true,
	"mongorestore": true,
	"mongosh":     true,

	// Redis
	"redis-cli": true,

	// SQLite
	"sqlite3": true,

	// General utilities
	"gzip":   true,
	"gunzip": true,
	"tar":    true,
	"zip":    true,
	"unzip":  true,
	"curl":   true,
	"wget":   true,

	// AWS CLI (for S3)
	"aws": true,

	// Restic (backup)
	"restic": true,

	// Borg (backup)
	"borg": true,
}

// ExecOperation executes a binary command.
type ExecOperation struct{}

// Execute runs the exec operation.
func (o *ExecOperation) Execute(ctx context.Context, step *plugin.Step, execCtx *ExecContext) error {
	// Check if binary is allowed
	if !AllowedBinaries[step.Binary] {
		return fmt.Errorf("binary %q is not in the allowed list", step.Binary)
	}

	// Build template data
	data := map[string]interface{}{
		"plugin":  execCtx.PluginName,
		"command": execCtx.CommandName,
		"config":  execCtx.Config,
		"storage": execCtx.Storage,
		"job_id":  execCtx.JobID,
		"tempdir": execCtx.TempDir,
		"vars":    execCtx.Variables,
	}

	// Render args
	args, err := RenderTemplateSlice(step.Args, data)
	if err != nil {
		return fmt.Errorf("render args: %w", err)
	}

	// Render env
	env, err := RenderTemplateMap(step.Env, data)
	if err != nil {
		return fmt.Errorf("render env: %w", err)
	}

	// Parse timeout
	timeout := 5 * time.Minute // default
	if step.Timeout != "" {
		parsed, err := time.ParseDuration(step.Timeout)
		if err != nil {
			return fmt.Errorf("parse timeout: %w", err)
		}
		timeout = parsed
	}

	// Create context with timeout
	ctx, cancel := context.WithTimeout(ctx, timeout)
	defer cancel()

	// Build command
	cmd := exec.CommandContext(ctx, step.Binary, args...)

	// Set environment
	cmd.Env = os.Environ()
	for k, v := range env {
		cmd.Env = append(cmd.Env, fmt.Sprintf("%s=%s", k, v))
	}

	// Handle stdout redirection
	var stdoutFile *os.File
	if step.Stdout != "" {
		path, err := RenderTemplate(step.Stdout, data)
		if err != nil {
			return fmt.Errorf("render stdout path: %w", err)
		}
		stdoutFile, err = os.Create(path)
		if err != nil {
			return fmt.Errorf("create stdout file: %w", err)
		}
		defer stdoutFile.Close()
		cmd.Stdout = stdoutFile
	} else {
		cmd.Stdout = io.Discard
	}

	// Capture stderr for logging
	cmd.Stderr = os.Stderr // TODO: capture and log

	execCtx.Logger.Info("executing command",
		"binary", step.Binary,
		"args", args,
		"timeout", timeout,
	)

	// Run command
	if err := cmd.Run(); err != nil {
		if ctx.Err() == context.DeadlineExceeded {
			return fmt.Errorf("command timed out after %v", timeout)
		}
		return fmt.Errorf("command failed: %w", err)
	}

	// Store output path in variables if we redirected stdout
	if step.Stdout != "" && step.ID != "" {
		execCtx.Variables[step.ID+"_output"] = step.Stdout
	}

	return nil
}
