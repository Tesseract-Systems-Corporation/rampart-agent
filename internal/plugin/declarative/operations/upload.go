package operations

import (
	"context"
	"fmt"
	"os"
	"path/filepath"
	"strings"

	"github.com/minio/minio-go/v7"
	"github.com/minio/minio-go/v7/pkg/credentials"

	"github.com/Tesseract-Systems-Corporation/rampart-agent/internal/plugin"
)

// UploadOperation uploads a file to storage (local or S3).
type UploadOperation struct{}

// Execute runs the upload operation.
func (o *UploadOperation) Execute(ctx context.Context, step *plugin.Step, execCtx *ExecContext) error {
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

	// Render source path
	sourcePath, err := RenderTemplate(step.Source, data)
	if err != nil {
		return fmt.Errorf("render source path: %w", err)
	}

	// Render destination path
	destPath, err := RenderTemplate(step.Destination, data)
	if err != nil {
		return fmt.Errorf("render destination path: %w", err)
	}

	// Determine storage type from context
	storageType := "local"
	if st, ok := execCtx.Storage["type"].(string); ok {
		storageType = st
	}

	switch storageType {
	case "local":
		return o.uploadLocal(ctx, sourcePath, destPath, execCtx)
	case "s3":
		return o.uploadS3(ctx, sourcePath, destPath, execCtx)
	default:
		return fmt.Errorf("unsupported storage type: %s", storageType)
	}
}

func (o *UploadOperation) uploadLocal(ctx context.Context, source, dest string, execCtx *ExecContext) error {
	execCtx.Logger.Info("copying file locally",
		"source", source,
		"destination", dest,
	)

	// Ensure destination directory exists
	destDir := filepath.Dir(dest)
	if err := os.MkdirAll(destDir, 0755); err != nil {
		return fmt.Errorf("create destination directory: %w", err)
	}

	// Read source
	data, err := os.ReadFile(source)
	if err != nil {
		return fmt.Errorf("read source file: %w", err)
	}

	// Write to destination
	if err := os.WriteFile(dest, data, 0644); err != nil {
		return fmt.Errorf("write destination file: %w", err)
	}

	// Store result in variables
	if execCtx.Variables != nil {
		execCtx.Variables["upload_path"] = dest
		info, err := os.Stat(dest)
		if err == nil {
			execCtx.Variables["upload_size"] = info.Size()
		}
	}

	return nil
}

func (o *UploadOperation) uploadS3(ctx context.Context, source, dest string, execCtx *ExecContext) error {
	// Get S3 configuration from storage context
	storage := execCtx.Storage

	endpoint, _ := storage["endpoint"].(string)
	accessKey, _ := storage["access_key"].(string)
	secretKey, _ := storage["secret_key"].(string)
	region, _ := storage["region"].(string)
	bucket, _ := storage["bucket"].(string)
	bucketPath, _ := storage["bucket_path"].(string)

	if endpoint == "" || accessKey == "" || secretKey == "" || bucket == "" {
		return fmt.Errorf("missing S3 configuration (endpoint, access_key, secret_key, bucket required)")
	}

	execCtx.Logger.Info("uploading to S3",
		"source", source,
		"endpoint", endpoint,
		"bucket", bucket,
	)

	// Parse the endpoint URL to get host
	useSSL := true
	if strings.HasPrefix(endpoint, "https://") {
		endpoint = strings.TrimPrefix(endpoint, "https://")
	} else if strings.HasPrefix(endpoint, "http://") {
		endpoint = strings.TrimPrefix(endpoint, "http://")
		useSSL = false
	}

	// Create minio client
	client, err := minio.New(endpoint, &minio.Options{
		Creds:  credentials.NewStaticV4(accessKey, secretKey, ""),
		Secure: useSSL,
		Region: region,
	})
	if err != nil {
		return fmt.Errorf("create S3 client: %w", err)
	}

	// Open source file
	file, err := os.Open(source)
	if err != nil {
		return fmt.Errorf("open source file: %w", err)
	}
	defer file.Close()

	// Get file info
	fileInfo, err := file.Stat()
	if err != nil {
		return fmt.Errorf("stat source file: %w", err)
	}

	// Build object key
	filename := filepath.Base(source)
	var key string
	if bucketPath != "" {
		key = bucketPath + "/" + filename
	} else {
		key = filename
	}

	// Upload
	_, err = client.PutObject(ctx, bucket, key, file, fileInfo.Size(), minio.PutObjectOptions{
		ContentType: "application/octet-stream",
	})
	if err != nil {
		return fmt.Errorf("upload to S3: %w", err)
	}

	// Store result in variables
	s3Path := fmt.Sprintf("s3://%s/%s", bucket, key)
	if execCtx.Variables != nil {
		execCtx.Variables["upload_path"] = s3Path
		execCtx.Variables["upload_size"] = fileInfo.Size()
	}

	execCtx.Logger.Info("uploaded to S3",
		"path", s3Path,
		"size", fileInfo.Size(),
	)

	return nil
}
