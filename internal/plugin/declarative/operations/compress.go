package operations

import (
	"compress/gzip"
	"context"
	"fmt"
	"io"
	"os"

	"github.com/Tesseract-Systems-Corporation/rampart-agent/internal/plugin"
)

// CompressOperation compresses a file using gzip.
type CompressOperation struct{}

// Execute runs the compress operation.
func (o *CompressOperation) Execute(ctx context.Context, step *plugin.Step, execCtx *ExecContext) error {
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

	// Render input path
	inputPath, err := RenderTemplate(step.Input, data)
	if err != nil {
		return fmt.Errorf("render input path: %w", err)
	}

	// Render output path
	outputPath, err := RenderTemplate(step.Output, data)
	if err != nil {
		return fmt.Errorf("render output path: %w", err)
	}

	// Determine algorithm (default to gzip)
	algorithm := step.Algorithm
	if algorithm == "" {
		algorithm = "gzip"
	}

	switch algorithm {
	case "gzip":
		return o.compressGzip(ctx, inputPath, outputPath, execCtx)
	default:
		return fmt.Errorf("unsupported compression algorithm: %s", algorithm)
	}
}

func (o *CompressOperation) compressGzip(ctx context.Context, input, output string, execCtx *ExecContext) error {
	// Open input file
	inFile, err := os.Open(input)
	if err != nil {
		return fmt.Errorf("open input file: %w", err)
	}
	defer inFile.Close()

	// Create output file
	outFile, err := os.Create(output)
	if err != nil {
		return fmt.Errorf("create output file: %w", err)
	}
	defer outFile.Close()

	// Create gzip writer
	gzWriter := gzip.NewWriter(outFile)
	defer gzWriter.Close()

	execCtx.Logger.Info("compressing file",
		"input", input,
		"output", output,
		"algorithm", "gzip",
	)

	// Copy with context cancellation check
	buf := make([]byte, 32*1024)
	for {
		select {
		case <-ctx.Done():
			return ctx.Err()
		default:
		}

		n, err := inFile.Read(buf)
		if n > 0 {
			if _, writeErr := gzWriter.Write(buf[:n]); writeErr != nil {
				return fmt.Errorf("write to gzip: %w", writeErr)
			}
		}
		if err == io.EOF {
			break
		}
		if err != nil {
			return fmt.Errorf("read input: %w", err)
		}
	}

	// Get output file size for variables
	if err := gzWriter.Close(); err != nil {
		return fmt.Errorf("close gzip writer: %w", err)
	}
	if err := outFile.Close(); err != nil {
		return fmt.Errorf("close output file: %w", err)
	}

	// Get file info
	info, err := os.Stat(output)
	if err == nil && execCtx.Variables != nil {
		execCtx.Variables["compressed_size"] = info.Size()
		execCtx.Variables["compressed_path"] = output
	}

	return nil
}
