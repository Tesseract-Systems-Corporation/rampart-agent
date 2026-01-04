// Package emitter handles sending events to the Rampart control plane.
package emitter

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"log/slog"
	"net/http"
	"os"
	"path/filepath"
	"sync"
	"sync/atomic"
	"time"

	"github.com/Tesseract-Systems-Corporation/rampart-agent/pkg/event"
)

// Default heartbeat interval - control plane may override this
const DefaultHeartbeatInterval = 30 * time.Second

// Config holds configuration for the Emitter.
type Config struct {
	// Endpoint is the URL of the control plane event ingestion endpoint.
	Endpoint string

	// APIKey is the API key for authentication.
	APIKey string

	// ServerID is the unique identifier for this server.
	ServerID string

	// ServerName is the human-friendly name for this server.
	ServerName string

	// Hostname is the hostname of this server.
	Hostname string

	// AgentVersion is the version of the agent.
	AgentVersion string

	// Provider is the cloud provider (aws, gcp, azure, oci, digitalocean, vultr, on-prem).
	Provider string

	// BatchSize is the maximum number of events per batch.
	// Defaults to 100 if zero.
	BatchSize int

	// FlushInterval is how often to flush events even if batch isn't full.
	// Defaults to 10 seconds if zero.
	FlushInterval time.Duration

	// BufferPath is the path to store events when offline.
	// If empty, buffering is disabled.
	BufferPath string

	// MaxRetries is the maximum number of retries for failed requests.
	// Defaults to 3 if zero.
	MaxRetries int

	// RetryDelay is the initial delay between retries.
	// Defaults to 1 second if zero.
	RetryDelay time.Duration

	// Logger is the logger to use. If nil, uses slog.Default().
	Logger *slog.Logger
}

// Emitter sends events to the control plane.
type Emitter struct {
	endpoint      string
	apiKey        string
	serverID      string
	serverName    string
	hostname      string
	agentVersion  string
	provider      string
	batchSize     int
	flushInterval time.Duration
	bufferPath    string
	maxRetries    int
	retryDelay    time.Duration
	logger        *slog.Logger
	client        *http.Client

	// buffer holds events waiting to be sent
	buffer []event.Event
	mu     sync.Mutex

	// input channel for receiving events
	input chan event.Event

	// metrics
	eventsSent  int64
	batchesSent int64
	errors      int64

	// command handler for control plane commands
	commandHandler CommandHandler

	// connection health tracking
	consecutiveFailures int64
	lastSuccessTime     time.Time
	isConnected         atomic.Bool
}

// EventBatch represents a batch of events to send.
type EventBatch struct {
	Events []event.Event `json:"events"`
}

// Metrics contains emitter statistics.
type Metrics struct {
	EventsSent  int64
	BatchesSent int64
	Errors      int64
	BufferSize  int
}

// New creates a new Emitter with the given configuration.
func New(cfg Config) *Emitter {
	batchSize := cfg.BatchSize
	if batchSize == 0 {
		batchSize = 100
	}

	flushInterval := cfg.FlushInterval
	if flushInterval == 0 {
		flushInterval = 10 * time.Second
	}

	maxRetries := cfg.MaxRetries
	if maxRetries == 0 {
		maxRetries = 3
	}

	retryDelay := cfg.RetryDelay
	if retryDelay == 0 {
		retryDelay = time.Second
	}

	logger := cfg.Logger
	if logger == nil {
		logger = slog.Default()
	}

	e := &Emitter{
		endpoint:        cfg.Endpoint,
		apiKey:          cfg.APIKey,
		serverID:        cfg.ServerID,
		serverName:      cfg.ServerName,
		hostname:        cfg.Hostname,
		agentVersion:    cfg.AgentVersion,
		provider:        cfg.Provider,
		batchSize:       batchSize,
		flushInterval:   flushInterval,
		bufferPath:      cfg.BufferPath,
		maxRetries:      maxRetries,
		retryDelay:      retryDelay,
		logger:          logger,
		client: &http.Client{
			Timeout: 10 * time.Second, // Shorter timeout to fail fast
			Transport: &http.Transport{
				MaxIdleConns:        10,
				IdleConnTimeout:     30 * time.Second,
				DisableKeepAlives:   false,
				MaxIdleConnsPerHost: 5,
			},
		},
		buffer:          make([]event.Event, 0, batchSize),
		input:           make(chan event.Event, 1000),
		lastSuccessTime: time.Now(),
	}
	e.isConnected.Store(true) // Optimistic start
	return e
}

// Send queues an event to be sent. This is non-blocking.
func (e *Emitter) Send(ev event.Event) {
	select {
	case e.input <- ev:
	default:
		// Channel full, buffer to disk if configured
		e.logger.Warn("event channel full, buffering")
		e.bufferEvent(ev)
	}
}

// Run starts the emitter. It blocks until the context is cancelled.
func (e *Emitter) Run(ctx context.Context) error {
	e.logger.Info("starting emitter",
		"endpoint", e.endpoint,
		"batch_size", e.batchSize,
		"flush_interval", e.flushInterval,
	)

	// Load any buffered events from disk
	e.loadBufferedEvents()

	// Current heartbeat interval - starts with default, updated by control plane
	heartbeatInterval := DefaultHeartbeatInterval

	// Send initial heartbeat to register the server and get interval
	if nextInterval, err := e.sendHeartbeat(ctx); err != nil {
		e.logger.Error("failed to send initial heartbeat", "error", err)
		e.markFailure()
	} else {
		e.logger.Info("server registered with control plane", "heartbeat_interval", nextInterval)
		e.markSuccess()
		if nextInterval > 0 {
			heartbeatInterval = nextInterval
		}
	}

	flushTicker := time.NewTicker(e.flushInterval)
	defer flushTicker.Stop()

	heartbeatTicker := time.NewTicker(heartbeatInterval)
	defer heartbeatTicker.Stop()

	for {
		select {
		case <-ctx.Done():
			e.logger.Info("emitter stopping, flushing remaining events")
			e.flush(context.Background()) // Use background context for final flush
			return ctx.Err()

		case ev := <-e.input:
			e.mu.Lock()
			e.buffer = append(e.buffer, ev)
			shouldFlush := len(e.buffer) >= e.batchSize
			e.mu.Unlock()

			if shouldFlush {
				e.flush(ctx)
			}

		case <-flushTicker.C:
			e.flush(ctx)

		case <-heartbeatTicker.C:
			// Use backoff interval if disconnected
			currentInterval := e.getHeartbeatInterval(heartbeatInterval)

			if nextInterval, err := e.sendHeartbeat(ctx); err != nil {
				e.markFailure()
				failures := atomic.LoadInt64(&e.consecutiveFailures)
				e.logger.Warn("heartbeat failed",
					"error", err,
					"consecutive_failures", failures,
					"next_retry", currentInterval)

				// Reset ticker with backoff interval
				heartbeatTicker.Reset(currentInterval)
			} else {
				wasDisconnected := !e.isConnected.Load()
				e.markSuccess()

				if wasDisconnected {
					e.logger.Info("connection restored to control plane")
				}

				if nextInterval > 0 && nextInterval != heartbeatInterval {
					e.logger.Info("heartbeat interval updated", "old", heartbeatInterval, "new", nextInterval)
					heartbeatInterval = nextInterval
				}
				heartbeatTicker.Reset(heartbeatInterval)
			}
		}
	}
}

// markSuccess records a successful connection.
func (e *Emitter) markSuccess() {
	atomic.StoreInt64(&e.consecutiveFailures, 0)
	e.lastSuccessTime = time.Now()
	e.isConnected.Store(true)
}

// markFailure records a connection failure.
func (e *Emitter) markFailure() {
	atomic.AddInt64(&e.consecutiveFailures, 1)
	e.isConnected.Store(false)
}

// getHeartbeatInterval returns the heartbeat interval with exponential backoff if disconnected.
func (e *Emitter) getHeartbeatInterval(baseInterval time.Duration) time.Duration {
	failures := atomic.LoadInt64(&e.consecutiveFailures)
	if failures == 0 {
		return baseInterval
	}

	// Exponential backoff: base * 2^(failures-1), capped at 5 minutes
	exp := failures - 1
	if exp > 4 {
		exp = 4 // Cap at 16x
	}
	backoff := baseInterval * time.Duration(1<<exp)
	maxBackoff := 5 * time.Minute
	if backoff > maxBackoff {
		backoff = maxBackoff
	}
	return backoff
}

// Command represents a command from the control plane.
type Command struct {
	ID      string          `json:"id"`
	Command string          `json:"command"`
	Payload json.RawMessage `json:"payload"`
}

// CommandHandler is a function that handles commands from the control plane.
type CommandHandler func(cmd Command)

// SetCommandHandler sets the handler for commands from the control plane.
func (e *Emitter) SetCommandHandler(handler CommandHandler) {
	e.commandHandler = handler
}

// heartbeatResponse is the response from the control plane heartbeat endpoint.
type heartbeatResponse struct {
	Status         string    `json:"status"`
	Error          string    `json:"error,omitempty"`
	NextIntervalMs int       `json:"next_interval_ms"`
	Commands       []Command `json:"commands,omitempty"`
}

// sendHeartbeat sends a heartbeat to register/update the server.
// Returns the next heartbeat interval suggested by the control plane.
func (e *Emitter) sendHeartbeat(ctx context.Context) (time.Duration, error) {
	payload := map[string]string{
		"server_id":     e.serverID,
		"name":          e.serverName,
		"hostname":      e.hostname,
		"agent_version": e.agentVersion,
		"provider":      e.provider,
	}

	data, err := json.Marshal(payload)
	if err != nil {
		return 0, fmt.Errorf("marshal heartbeat: %w", err)
	}

	req, err := http.NewRequestWithContext(ctx, http.MethodPost, e.endpoint+"/agent/heartbeat", bytes.NewReader(data))
	if err != nil {
		return 0, fmt.Errorf("create request: %w", err)
	}

	req.Header.Set("Authorization", "Bearer "+e.apiKey)
	req.Header.Set("Content-Type", "application/json")

	resp, err := e.client.Do(req)
	if err != nil {
		return 0, fmt.Errorf("request failed: %w", err)
	}
	defer resp.Body.Close()

	// Parse response
	var hbResp heartbeatResponse
	if err := json.NewDecoder(resp.Body).Decode(&hbResp); err != nil {
		// If we can't parse the response, just check status code
		if resp.StatusCode < 200 || resp.StatusCode >= 300 {
			return 0, fmt.Errorf("heartbeat failed with status: %d", resp.StatusCode)
		}
		return 0, nil
	}

	// Handle rate limiting (429) - use the interval from the response
	if resp.StatusCode == http.StatusTooManyRequests {
		e.logger.Warn("heartbeat rate limited", "next_interval_ms", hbResp.NextIntervalMs)
		return time.Duration(hbResp.NextIntervalMs) * time.Millisecond, nil
	}

	if resp.StatusCode < 200 || resp.StatusCode >= 300 {
		return 0, fmt.Errorf("heartbeat failed with status: %d, error: %s", resp.StatusCode, hbResp.Error)
	}

	// Process any commands from the control plane
	if len(hbResp.Commands) > 0 && e.commandHandler != nil {
		for _, cmd := range hbResp.Commands {
			e.logger.Info("received command from control plane", "command", cmd.Command, "id", cmd.ID)
			go e.commandHandler(cmd)
		}
	}

	// Return the interval from the control plane
	return time.Duration(hbResp.NextIntervalMs) * time.Millisecond, nil
}

// flush sends all buffered events to the control plane.
func (e *Emitter) flush(ctx context.Context) {
	e.mu.Lock()
	if len(e.buffer) == 0 {
		e.mu.Unlock()
		return
	}

	// Take ownership of buffer
	events := e.buffer
	e.buffer = make([]event.Event, 0, e.batchSize)
	e.mu.Unlock()

	// Send in batches
	for i := 0; i < len(events); i += e.batchSize {
		end := i + e.batchSize
		if end > len(events) {
			end = len(events)
		}

		batch := events[i:end]
		if err := e.sendBatch(ctx, batch); err != nil {
			e.logger.Error("failed to send batch", "error", err, "batch_size", len(batch))
			atomic.AddInt64(&e.errors, 1)

			// Buffer failed events
			for _, ev := range batch {
				e.bufferEvent(ev)
			}
		} else {
			atomic.AddInt64(&e.eventsSent, int64(len(batch)))
			atomic.AddInt64(&e.batchesSent, 1)
		}
	}
}

// sendBatch sends a batch of events with retry logic.
func (e *Emitter) sendBatch(ctx context.Context, events []event.Event) error {
	batch := EventBatch{Events: events}

	data, err := json.Marshal(batch)
	if err != nil {
		return fmt.Errorf("marshal batch: %w", err)
	}

	var lastErr error
	for attempt := 0; attempt <= e.maxRetries; attempt++ {
		if attempt > 0 {
			delay := e.retryDelay * time.Duration(1<<(attempt-1)) // Exponential backoff
			select {
			case <-ctx.Done():
				return ctx.Err()
			case <-time.After(delay):
			}
		}

		req, err := http.NewRequestWithContext(ctx, http.MethodPost, e.endpoint+"/agent/events", bytes.NewReader(data))
		if err != nil {
			return fmt.Errorf("create request: %w", err)
		}

		req.Header.Set("Authorization", "Bearer "+e.apiKey)
		req.Header.Set("Content-Type", "application/json")

		resp, err := e.client.Do(req)
		if err != nil {
			lastErr = fmt.Errorf("request failed: %w", err)
			continue
		}
		resp.Body.Close()

		if resp.StatusCode >= 200 && resp.StatusCode < 300 {
			return nil
		}

		if resp.StatusCode >= 500 {
			lastErr = fmt.Errorf("server error: %d", resp.StatusCode)
			continue // Retry on server errors
		}

		// Client error - don't retry
		return fmt.Errorf("client error: %d", resp.StatusCode)
	}

	return fmt.Errorf("max retries exceeded: %w", lastErr)
}

// bufferEvent writes an event to disk for later sending.
func (e *Emitter) bufferEvent(ev event.Event) {
	if e.bufferPath == "" {
		return
	}

	// Ensure buffer directory exists
	if err := os.MkdirAll(e.bufferPath, 0755); err != nil {
		e.logger.Error("failed to create buffer directory", "error", err)
		return
	}

	// Write event to file
	filename := filepath.Join(e.bufferPath, ev.ID+".json")
	data, err := json.Marshal(ev)
	if err != nil {
		e.logger.Error("failed to marshal event for buffer", "error", err)
		return
	}

	if err := os.WriteFile(filename, data, 0644); err != nil {
		e.logger.Error("failed to write event to buffer", "error", err)
	}
}

// loadBufferedEvents loads any previously buffered events from disk.
func (e *Emitter) loadBufferedEvents() {
	if e.bufferPath == "" {
		return
	}

	files, err := os.ReadDir(e.bufferPath)
	if err != nil {
		if !os.IsNotExist(err) {
			e.logger.Error("failed to read buffer directory", "error", err)
		}
		return
	}

	for _, file := range files {
		if file.IsDir() || filepath.Ext(file.Name()) != ".json" {
			continue
		}

		path := filepath.Join(e.bufferPath, file.Name())
		data, err := os.ReadFile(path)
		if err != nil {
			e.logger.Error("failed to read buffered event", "path", path, "error", err)
			continue
		}

		var ev event.Event
		if err := json.Unmarshal(data, &ev); err != nil {
			e.logger.Error("failed to unmarshal buffered event", "path", path, "error", err)
			continue
		}

		// Queue the event
		e.mu.Lock()
		e.buffer = append(e.buffer, ev)
		e.mu.Unlock()

		// Remove the file
		os.Remove(path)
	}

	e.mu.Lock()
	count := len(e.buffer)
	e.mu.Unlock()

	if count > 0 {
		e.logger.Info("loaded buffered events", "count", count)
	}
}

// Metrics returns current emitter statistics.
func (e *Emitter) Metrics() Metrics {
	e.mu.Lock()
	bufferSize := len(e.buffer)
	e.mu.Unlock()

	return Metrics{
		EventsSent:  atomic.LoadInt64(&e.eventsSent),
		BatchesSent: atomic.LoadInt64(&e.batchesSent),
		Errors:      atomic.LoadInt64(&e.errors),
		BufferSize:  bufferSize,
	}
}
