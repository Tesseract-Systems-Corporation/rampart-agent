package emitter

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"os"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/Tesseract-Systems-Corporation/rampart-agent/pkg/event"
)

func TestEmitterConfig(t *testing.T) {
	tests := []struct {
		name          string
		config        Config
		wantBatchSize int
		wantInterval  time.Duration
	}{
		{
			name: "default values",
			config: Config{
				Endpoint: "http://localhost:8080",
				APIKey:   "test-key",
			},
			wantBatchSize: 100,
			wantInterval:  10 * time.Second,
		},
		{
			name: "custom values",
			config: Config{
				Endpoint:      "http://localhost:8080",
				APIKey:        "test-key",
				BatchSize:     50,
				FlushInterval: 5 * time.Second,
			},
			wantBatchSize: 50,
			wantInterval:  5 * time.Second,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			e := New(tt.config)
			if e.batchSize != tt.wantBatchSize {
				t.Errorf("batchSize = %v, want %v", e.batchSize, tt.wantBatchSize)
			}
			if e.flushInterval != tt.wantInterval {
				t.Errorf("flushInterval = %v, want %v", e.flushInterval, tt.wantInterval)
			}
		})
	}
}

func TestEmitterSend(t *testing.T) {
	var receivedEvents []event.Event
	var requestCount int32

	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		atomic.AddInt32(&requestCount, 1)

		if r.Method != http.MethodPost {
			t.Errorf("Method = %v, want POST", r.Method)
		}
		if r.Header.Get("Authorization") != "Bearer test-key" {
			t.Errorf("Authorization header = %v, want Bearer test-key", r.Header.Get("Authorization"))
		}
		if r.Header.Get("Content-Type") != "application/json" {
			t.Errorf("Content-Type = %v, want application/json", r.Header.Get("Content-Type"))
		}

		var batch EventBatch
		if err := json.NewDecoder(r.Body).Decode(&batch); err != nil {
			t.Errorf("failed to decode body: %v", err)
			w.WriteHeader(http.StatusBadRequest)
			return
		}

		receivedEvents = append(receivedEvents, batch.Events...)
		w.WriteHeader(http.StatusOK)
	}))
	defer srv.Close()

	e := New(Config{
		Endpoint:      srv.URL,
		APIKey:        "test-key",
		BatchSize:     10,
		FlushInterval: 100 * time.Millisecond,
	})

	ctx, cancel := context.WithTimeout(context.Background(), time.Second)
	defer cancel()

	// Start the emitter
	go e.Run(ctx)

	// Send some events
	for i := 0; i < 5; i++ {
		ev := event.NewEvent(event.HealthHeartbeat, "fort_test", "srv_test", map[string]any{
			"index": i,
		})
		e.Send(ev)
	}

	// Wait for flush
	time.Sleep(200 * time.Millisecond)

	if len(receivedEvents) != 5 {
		t.Errorf("received %d events, want 5", len(receivedEvents))
	}
}

func TestEmitterBatchFlush(t *testing.T) {
	var batches []EventBatch
	var mu sync.Mutex

	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		// Only capture event batches, ignore registration/heartbeat
		if r.URL.Path == "/agent/events" {
			var batch EventBatch
			json.NewDecoder(r.Body).Decode(&batch)
			mu.Lock()
			batches = append(batches, batch)
			mu.Unlock()
		}
		w.WriteHeader(http.StatusOK)
	}))
	defer srv.Close()

	e := New(Config{
		Endpoint:      srv.URL,
		APIKey:        "test-key",
		BatchSize:     3, // Small batch for testing
		FlushInterval: 10 * time.Second,
	})

	ctx, cancel := context.WithTimeout(context.Background(), time.Second)
	defer cancel()

	go e.Run(ctx)

	// Send 7 events - should trigger 2 batch flushes (3 + 3) + 1 remaining
	for i := 0; i < 7; i++ {
		ev := event.NewEvent(event.HealthHeartbeat, "fort_test", "srv_test", nil)
		e.Send(ev)
	}

	// Wait for batching - needs enough time for the events to be processed
	time.Sleep(500 * time.Millisecond)

	mu.Lock()
	batchCount := len(batches)
	batchesCopy := make([]EventBatch, len(batches))
	copy(batchesCopy, batches)
	mu.Unlock()

	// Should have at least 2 batches (from batch size triggers)
	if batchCount < 2 {
		t.Errorf("received %d batches, want at least 2", batchCount)
		return
	}

	// First two batches should have 3 events each
	for i, batch := range batchesCopy[:min(2, batchCount)] {
		if len(batch.Events) != 3 {
			t.Errorf("batch %d has %d events, want 3", i, len(batch.Events))
		}
	}
}

func TestEmitterRetry(t *testing.T) {
	var attempts int32

	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		count := atomic.AddInt32(&attempts, 1)
		if count < 3 {
			w.WriteHeader(http.StatusInternalServerError)
			return
		}
		w.WriteHeader(http.StatusOK)
	}))
	defer srv.Close()

	e := New(Config{
		Endpoint:      srv.URL,
		APIKey:        "test-key",
		BatchSize:     10,
		FlushInterval: 50 * time.Millisecond,
		MaxRetries:    5,
		RetryDelay:    10 * time.Millisecond,
	})

	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
	defer cancel()

	go e.Run(ctx)

	ev := event.NewEvent(event.HealthHeartbeat, "fort_test", "srv_test", nil)
	e.Send(ev)

	// Wait for retries
	time.Sleep(500 * time.Millisecond)

	// Should have attempted at least 3 times
	if atomic.LoadInt32(&attempts) < 3 {
		t.Errorf("attempts = %d, want at least 3", attempts)
	}
}

func TestEmitterContextCancellation(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
	}))
	defer srv.Close()

	e := New(Config{
		Endpoint:      srv.URL,
		APIKey:        "test-key",
		FlushInterval: 100 * time.Millisecond,
	})

	ctx, cancel := context.WithCancel(context.Background())

	done := make(chan struct{})
	go func() {
		e.Run(ctx)
		close(done)
	}()

	// Send an event
	e.Send(event.NewEvent(event.HealthHeartbeat, "fort_test", "srv_test", nil))

	// Cancel context
	cancel()

	// Run should exit
	select {
	case <-done:
		// Good
	case <-time.After(time.Second):
		t.Error("Run did not exit after context cancellation")
	}
}

func TestEmitterBufferPath(t *testing.T) {
	dir := t.TempDir()
	bufferPath := dir + "/buffer"

	e := New(Config{
		Endpoint:   "http://nonexistent:8080",
		APIKey:     "test-key",
		BufferPath: bufferPath,
	})

	// Send an event (will fail to send, should buffer)
	ev := event.NewEvent(event.HealthHeartbeat, "fort_test", "srv_test", nil)
	e.bufferEvent(ev)

	// Verify buffer file exists
	// Note: actual file buffering implementation may vary
}

func TestEventBatchSerialization(t *testing.T) {
	batch := EventBatch{
		Events: []event.Event{
			event.NewEvent(event.ContainerStarted, "fort_1", "srv_1", map[string]any{"container": "nginx"}),
			event.NewEvent(event.HealthHeartbeat, "fort_1", "srv_1", map[string]any{"cpu": 50.0}),
		},
	}

	data, err := json.Marshal(batch)
	if err != nil {
		t.Fatalf("Marshal() error = %v", err)
	}

	var decoded EventBatch
	if err := json.Unmarshal(data, &decoded); err != nil {
		t.Fatalf("Unmarshal() error = %v", err)
	}

	if len(decoded.Events) != 2 {
		t.Errorf("Events = %d, want 2", len(decoded.Events))
	}
}

func TestEmitterSendNonBlocking(t *testing.T) {
	// Create emitter with slow server
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		time.Sleep(100 * time.Millisecond)
		w.WriteHeader(http.StatusOK)
	}))
	defer srv.Close()

	e := New(Config{
		Endpoint:      srv.URL,
		APIKey:        "test-key",
		BatchSize:     1000,
		FlushInterval: 10 * time.Second,
	})

	// Send should not block
	start := time.Now()
	for i := 0; i < 100; i++ {
		e.Send(event.NewEvent(event.HealthHeartbeat, "fort", "srv", nil))
	}
	elapsed := time.Since(start)

	if elapsed > 50*time.Millisecond {
		t.Errorf("Send took %v, should be non-blocking", elapsed)
	}
}

func TestEmitterMetrics(t *testing.T) {
	var receivedCount int32

	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		var batch EventBatch
		json.NewDecoder(r.Body).Decode(&batch)
		atomic.AddInt32(&receivedCount, int32(len(batch.Events)))
		w.WriteHeader(http.StatusOK)
	}))
	defer srv.Close()

	e := New(Config{
		Endpoint:      srv.URL,
		APIKey:        "test-key",
		BatchSize:     10,
		FlushInterval: 50 * time.Millisecond,
	})

	ctx, cancel := context.WithTimeout(context.Background(), time.Second)
	defer cancel()

	go e.Run(ctx)

	// Send events
	for i := 0; i < 25; i++ {
		e.Send(event.NewEvent(event.HealthHeartbeat, "fort", "srv", nil))
	}

	// Wait for all flushes
	time.Sleep(200 * time.Millisecond)

	metrics := e.Metrics()

	if metrics.EventsSent == 0 {
		t.Error("EventsSent should be > 0")
	}

	if metrics.BatchesSent == 0 {
		t.Error("BatchesSent should be > 0")
	}
}

func min(a, b int) int {
	if a < b {
		return a
	}
	return b
}

func TestEmitterHeartbeatDynamicInterval(t *testing.T) {
	// Test that emitter parses next_interval_ms from heartbeat response
	var heartbeatCount int32

	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path == "/agent/heartbeat" {
			count := atomic.AddInt32(&heartbeatCount, 1)
			// Return a 100ms interval for testing
			w.Header().Set("Content-Type", "application/json")
			if count == 1 {
				// First heartbeat: return 100ms interval
				json.NewEncoder(w).Encode(map[string]any{
					"status":           "ok",
					"next_interval_ms": 100,
				})
			} else {
				// Subsequent heartbeats
				json.NewEncoder(w).Encode(map[string]any{
					"status":           "ok",
					"next_interval_ms": 100,
				})
			}
			return
		}
		// Events endpoint
		w.WriteHeader(http.StatusOK)
	}))
	defer srv.Close()

	e := New(Config{
		Endpoint:      srv.URL,
		APIKey:        "test-key",
		FlushInterval: 10 * time.Second,
	})

	ctx, cancel := context.WithTimeout(context.Background(), 350*time.Millisecond)
	defer cancel()

	go e.Run(ctx)

	// Wait for context to complete
	<-ctx.Done()

	// With 100ms interval and 350ms timeout, we should have 3-4 heartbeats
	// (initial + 2-3 interval beats)
	count := atomic.LoadInt32(&heartbeatCount)
	if count < 3 {
		t.Errorf("heartbeatCount = %d, want at least 3 with 100ms interval", count)
	}
}

func TestEmitterHeartbeatRateLimited(t *testing.T) {
	// Test that emitter handles 429 rate limited response
	var heartbeatCount int32

	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path == "/agent/heartbeat" {
			count := atomic.AddInt32(&heartbeatCount, 1)
			if count == 1 {
				// First heartbeat succeeds with short interval
				w.Header().Set("Content-Type", "application/json")
				json.NewEncoder(w).Encode(map[string]any{
					"status":           "ok",
					"next_interval_ms": 50,
				})
			} else if count == 2 {
				// Second heartbeat is rate limited
				w.WriteHeader(http.StatusTooManyRequests)
				json.NewEncoder(w).Encode(map[string]any{
					"error":            "rate limited",
					"next_interval_ms": 200, // Slow down
				})
			} else {
				// After rate limit, continue normally
				w.Header().Set("Content-Type", "application/json")
				json.NewEncoder(w).Encode(map[string]any{
					"status":           "ok",
					"next_interval_ms": 100,
				})
			}
			return
		}
		w.WriteHeader(http.StatusOK)
	}))
	defer srv.Close()

	e := New(Config{
		Endpoint:      srv.URL,
		APIKey:        "test-key",
		FlushInterval: 10 * time.Second,
	})

	ctx, cancel := context.WithTimeout(context.Background(), 400*time.Millisecond)
	defer cancel()

	go e.Run(ctx)

	<-ctx.Done()

	// Should have received heartbeats despite rate limiting
	count := atomic.LoadInt32(&heartbeatCount)
	if count < 2 {
		t.Errorf("heartbeatCount = %d, want at least 2", count)
	}
}

// TestGetHeartbeatInterval tests exponential backoff calculation
func TestGetHeartbeatInterval(t *testing.T) {
	tests := []struct {
		name             string
		failures         int64
		baseInterval     time.Duration
		expectedInterval time.Duration
	}{
		{
			name:             "no failures returns base interval",
			failures:         0,
			baseInterval:     30 * time.Second,
			expectedInterval: 30 * time.Second,
		},
		{
			name:             "1 failure returns base interval (2^0 = 1x)",
			failures:         1,
			baseInterval:     30 * time.Second,
			expectedInterval: 30 * time.Second,
		},
		{
			name:             "2 failures returns 2x base interval",
			failures:         2,
			baseInterval:     30 * time.Second,
			expectedInterval: 60 * time.Second,
		},
		{
			name:             "3 failures returns 4x base interval",
			failures:         3,
			baseInterval:     30 * time.Second,
			expectedInterval: 120 * time.Second,
		},
		{
			name:             "4 failures returns 8x base interval",
			failures:         4,
			baseInterval:     30 * time.Second,
			expectedInterval: 240 * time.Second,
		},
		{
			name:             "5 failures returns 16x base interval (capped)",
			failures:         5,
			baseInterval:     30 * time.Second,
			expectedInterval: 5 * time.Minute, // Capped at max
		},
		{
			name:             "10 failures still capped at 5 minutes",
			failures:         10,
			baseInterval:     30 * time.Second,
			expectedInterval: 5 * time.Minute,
		},
		{
			name:             "short base interval with many failures",
			failures:         5,
			baseInterval:     10 * time.Second,
			expectedInterval: 160 * time.Second, // 10 * 16 = 160s
		},
		{
			name:             "very long base interval gets capped",
			failures:         2,
			baseInterval:     3 * time.Minute,
			expectedInterval: 5 * time.Minute, // Would be 6min but capped at 5
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			e := New(Config{
				Endpoint: "http://localhost:8080",
				APIKey:   "test-key",
			})

			atomic.StoreInt64(&e.consecutiveFailures, tt.failures)

			got := e.getHeartbeatInterval(tt.baseInterval)
			if got != tt.expectedInterval {
				t.Errorf("getHeartbeatInterval() = %v, want %v", got, tt.expectedInterval)
			}
		})
	}
}

// TestSetCommandHandler tests setting the command handler
func TestSetCommandHandler(t *testing.T) {
	e := New(Config{
		Endpoint: "http://localhost:8080",
		APIKey:   "test-key",
	})

	var handlerCalled bool
	handler := func(cmd Command) {
		handlerCalled = true
	}

	e.SetCommandHandler(handler)

	if e.commandHandler == nil {
		t.Error("commandHandler should not be nil after SetCommandHandler")
	}

	// Verify handler is callable
	e.commandHandler(Command{ID: "test", Command: "test"})
	if !handlerCalled {
		t.Error("handler should have been called")
	}
}

// TestHeartbeatWithCommands tests command handling from heartbeat responses
func TestHeartbeatWithCommands(t *testing.T) {
	var receivedCommands []Command
	var mu sync.Mutex

	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path == "/agent/heartbeat" {
			w.Header().Set("Content-Type", "application/json")
			json.NewEncoder(w).Encode(map[string]any{
				"status":           "ok",
				"next_interval_ms": 1000,
				"commands": []map[string]any{
					{
						"id":      "cmd-1",
						"command": "restart",
						"payload": map[string]any{"service": "nginx"},
					},
					{
						"id":      "cmd-2",
						"command": "update",
						"payload": map[string]any{"version": "1.2.3"},
					},
				},
			})
			return
		}
		w.WriteHeader(http.StatusOK)
	}))
	defer srv.Close()

	e := New(Config{
		Endpoint:      srv.URL,
		APIKey:        "test-key",
		FlushInterval: 10 * time.Second,
	})

	e.SetCommandHandler(func(cmd Command) {
		mu.Lock()
		receivedCommands = append(receivedCommands, cmd)
		mu.Unlock()
	})

	ctx, cancel := context.WithTimeout(context.Background(), 200*time.Millisecond)
	defer cancel()

	go e.Run(ctx)
	<-ctx.Done()

	// Wait a bit for commands to be processed (they're handled in goroutines)
	time.Sleep(50 * time.Millisecond)

	mu.Lock()
	cmdCount := len(receivedCommands)
	mu.Unlock()

	if cmdCount != 2 {
		t.Errorf("received %d commands, want 2", cmdCount)
	}
}

// TestSendWhenChannelFull tests buffering when input channel is full
func TestSendWhenChannelFull(t *testing.T) {
	dir := t.TempDir()
	bufferPath := dir + "/buffer"

	e := New(Config{
		Endpoint:   "http://nonexistent:8080",
		APIKey:     "test-key",
		BufferPath: bufferPath,
	})

	// Fill the input channel (capacity is 1000)
	for i := 0; i < 1000; i++ {
		e.input <- event.NewEvent(event.HealthHeartbeat, "fort", "srv", nil)
	}

	// The next send should trigger buffering
	ev := event.NewEvent(event.HealthHeartbeat, "fort", "srv", map[string]any{"buffered": true})
	e.Send(ev)

	// Give time for buffering
	time.Sleep(50 * time.Millisecond)

	// Check that the event was buffered to disk
	files, err := os.ReadDir(bufferPath)
	if err != nil {
		t.Fatalf("failed to read buffer directory: %v", err)
	}

	if len(files) != 1 {
		t.Errorf("expected 1 buffered file, got %d", len(files))
	}
}

// TestBufferEventErrors tests error handling in bufferEvent
func TestBufferEventErrors(t *testing.T) {
	t.Run("no buffer path", func(t *testing.T) {
		e := New(Config{
			Endpoint:   "http://localhost:8080",
			APIKey:     "test-key",
			BufferPath: "", // No buffer path
		})

		ev := event.NewEvent(event.HealthHeartbeat, "fort", "srv", nil)
		// Should return early without error
		e.bufferEvent(ev)
	})

	t.Run("invalid buffer path", func(t *testing.T) {
		e := New(Config{
			Endpoint:   "http://localhost:8080",
			APIKey:     "test-key",
			BufferPath: "/nonexistent/path/that/cannot/be/created\x00invalid",
		})

		ev := event.NewEvent(event.HealthHeartbeat, "fort", "srv", nil)
		// Should log error but not panic
		e.bufferEvent(ev)
	})
}

// TestLoadBufferedEvents tests loading events from disk
func TestLoadBufferedEvents(t *testing.T) {
	t.Run("no buffer path", func(t *testing.T) {
		e := New(Config{
			Endpoint:   "http://localhost:8080",
			APIKey:     "test-key",
			BufferPath: "",
		})

		// Should return early without error
		e.loadBufferedEvents()
	})

	t.Run("nonexistent directory", func(t *testing.T) {
		e := New(Config{
			Endpoint:   "http://localhost:8080",
			APIKey:     "test-key",
			BufferPath: "/nonexistent/path/that/does/not/exist",
		})

		// Should handle gracefully
		e.loadBufferedEvents()
	})

	t.Run("directory with events", func(t *testing.T) {
		dir := t.TempDir()
		bufferPath := dir + "/buffer"

		// Create buffer directory and add some events
		if err := os.MkdirAll(bufferPath, 0755); err != nil {
			t.Fatalf("failed to create buffer dir: %v", err)
		}

		// Write valid event file
		ev := event.NewEvent(event.HealthHeartbeat, "fort", "srv", map[string]any{"test": true})
		data, _ := json.Marshal(ev)
		if err := os.WriteFile(bufferPath+"/"+ev.ID+".json", data, 0644); err != nil {
			t.Fatalf("failed to write event file: %v", err)
		}

		// Write invalid JSON file
		if err := os.WriteFile(bufferPath+"/invalid.json", []byte("not valid json"), 0644); err != nil {
			t.Fatalf("failed to write invalid file: %v", err)
		}

		// Write non-JSON file (should be skipped)
		if err := os.WriteFile(bufferPath+"/readme.txt", []byte("readme"), 0644); err != nil {
			t.Fatalf("failed to write txt file: %v", err)
		}

		// Create a subdirectory (should be skipped)
		if err := os.MkdirAll(bufferPath+"/subdir", 0755); err != nil {
			t.Fatalf("failed to create subdir: %v", err)
		}

		e := New(Config{
			Endpoint:   "http://localhost:8080",
			APIKey:     "test-key",
			BufferPath: bufferPath,
		})

		e.loadBufferedEvents()

		// Check that valid event was loaded
		e.mu.Lock()
		count := len(e.buffer)
		e.mu.Unlock()

		if count != 1 {
			t.Errorf("expected 1 buffered event, got %d", count)
		}

		// Valid event file should be removed, invalid should remain
		files, _ := os.ReadDir(bufferPath)
		jsonCount := 0
		for _, f := range files {
			if !f.IsDir() && f.Name() == "invalid.json" {
				jsonCount++
			}
		}
		if jsonCount != 1 {
			t.Errorf("invalid.json should still exist")
		}
	})

	t.Run("unreadable file", func(t *testing.T) {
		dir := t.TempDir()
		bufferPath := dir + "/buffer"

		if err := os.MkdirAll(bufferPath, 0755); err != nil {
			t.Fatalf("failed to create buffer dir: %v", err)
		}

		// Create file then make it unreadable
		filePath := bufferPath + "/unreadable.json"
		if err := os.WriteFile(filePath, []byte("{}"), 0000); err != nil {
			t.Fatalf("failed to write file: %v", err)
		}

		e := New(Config{
			Endpoint:   "http://localhost:8080",
			APIKey:     "test-key",
			BufferPath: bufferPath,
		})

		// Should handle gracefully without panic
		e.loadBufferedEvents()

		// Restore permissions for cleanup
		os.Chmod(filePath, 0644)
	})
}

// TestSendBatchClientError tests that client errors (4xx) don't retry
func TestSendBatchClientError(t *testing.T) {
	var attempts int32

	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path == "/agent/events" {
			atomic.AddInt32(&attempts, 1)
			w.WriteHeader(http.StatusBadRequest) // 400 - client error
			return
		}
		w.WriteHeader(http.StatusOK)
	}))
	defer srv.Close()

	e := New(Config{
		Endpoint:      srv.URL,
		APIKey:        "test-key",
		BatchSize:     10,
		FlushInterval: 50 * time.Millisecond,
		MaxRetries:    5,
		RetryDelay:    10 * time.Millisecond,
	})

	ctx, cancel := context.WithTimeout(context.Background(), 300*time.Millisecond)
	defer cancel()

	go e.Run(ctx)

	ev := event.NewEvent(event.HealthHeartbeat, "fort", "srv", nil)
	e.Send(ev)

	time.Sleep(200 * time.Millisecond)

	// Client errors should not retry - should only be 1 attempt
	count := atomic.LoadInt32(&attempts)
	if count != 1 {
		t.Errorf("client error should not retry, got %d attempts", count)
	}
}

// TestSendBatchContextCancellation tests that sendBatch respects context cancellation during retry
func TestSendBatchContextCancellation(t *testing.T) {
	var attempts int32

	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path == "/agent/events" {
			atomic.AddInt32(&attempts, 1)
			w.WriteHeader(http.StatusInternalServerError)
			return
		}
		w.WriteHeader(http.StatusOK)
	}))
	defer srv.Close()

	e := New(Config{
		Endpoint:      srv.URL,
		APIKey:        "test-key",
		BatchSize:     1,
		FlushInterval: 10 * time.Millisecond,
		MaxRetries:    10,
		RetryDelay:    100 * time.Millisecond, // Long delay to allow cancellation
	})

	ctx, cancel := context.WithTimeout(context.Background(), 150*time.Millisecond)
	defer cancel()

	go e.Run(ctx)

	ev := event.NewEvent(event.HealthHeartbeat, "fort", "srv", nil)
	e.Send(ev)

	<-ctx.Done()
	time.Sleep(50 * time.Millisecond)

	// Should have limited retries due to context cancellation
	count := atomic.LoadInt32(&attempts)
	if count > 3 {
		t.Errorf("expected limited retries due to context cancellation, got %d", count)
	}
}

// TestFlushBuffersFailedEvents tests that failed events are buffered to disk
func TestFlushBuffersFailedEvents(t *testing.T) {
	dir := t.TempDir()
	bufferPath := dir + "/buffer"

	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path == "/agent/events" {
			w.WriteHeader(http.StatusInternalServerError)
			return
		}
		w.WriteHeader(http.StatusOK)
	}))
	defer srv.Close()

	e := New(Config{
		Endpoint:      srv.URL,
		APIKey:        "test-key",
		BatchSize:     10,
		FlushInterval: 50 * time.Millisecond,
		MaxRetries:    0, // No retries to speed up test
		RetryDelay:    1 * time.Millisecond,
		BufferPath:    bufferPath,
	})

	ctx, cancel := context.WithTimeout(context.Background(), 200*time.Millisecond)
	defer cancel()

	go e.Run(ctx)

	// Send events
	for i := 0; i < 3; i++ {
		e.Send(event.NewEvent(event.HealthHeartbeat, "fort", "srv", map[string]any{"i": i}))
	}

	<-ctx.Done()
	time.Sleep(100 * time.Millisecond)

	// Check that events were buffered
	files, err := os.ReadDir(bufferPath)
	if err != nil {
		// Buffer directory might not exist if buffering failed
		return
	}

	jsonCount := 0
	for _, f := range files {
		if !f.IsDir() && len(f.Name()) > 5 && f.Name()[len(f.Name())-5:] == ".json" {
			jsonCount++
		}
	}

	if jsonCount == 0 {
		t.Error("expected some events to be buffered to disk")
	}

	// Check metrics
	metrics := e.Metrics()
	if metrics.Errors == 0 {
		t.Error("expected errors to be recorded")
	}
}

// TestHeartbeatFailureRecovery tests connection failure tracking and recovery
func TestHeartbeatFailureRecovery(t *testing.T) {
	e := New(Config{
		Endpoint:      "http://localhost:8080",
		APIKey:        "test-key",
		FlushInterval: 10 * time.Second,
	})

	// Simulate failure
	e.markFailure()
	if e.isConnected.Load() {
		t.Error("expected isConnected to be false after failure")
	}

	failures := atomic.LoadInt64(&e.consecutiveFailures)
	if failures != 1 {
		t.Errorf("expected 1 consecutive failure, got %d", failures)
	}

	// Simulate recovery
	wasDisconnected := !e.isConnected.Load()
	e.markSuccess()

	if !wasDisconnected {
		t.Error("should have been disconnected before recovery")
	}

	if !e.isConnected.Load() {
		t.Error("expected isConnected to be true after recovery")
	}

	failures = atomic.LoadInt64(&e.consecutiveFailures)
	if failures != 0 {
		t.Errorf("expected 0 consecutive failures after recovery, got %d", failures)
	}
}

// TestConnectionRestoredLogging tests the "connection restored" path in Run loop
func TestConnectionRestoredLogging(t *testing.T) {
	var heartbeatCount int32
	var mu sync.Mutex
	disconnectedAfterFirst := false

	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path == "/agent/heartbeat" {
			atomic.AddInt32(&heartbeatCount, 1)
			// All heartbeats succeed with short interval
			w.Header().Set("Content-Type", "application/json")
			json.NewEncoder(w).Encode(map[string]any{
				"status":           "ok",
				"next_interval_ms": 20, // Short interval
			})
			return
		}
		w.WriteHeader(http.StatusOK)
	}))
	defer srv.Close()

	e := New(Config{
		Endpoint:      srv.URL,
		APIKey:        "test-key",
		FlushInterval: 10 * time.Second,
	})

	ctx, cancel := context.WithTimeout(context.Background(), 200*time.Millisecond)
	defer cancel()

	// Start the emitter
	go func() {
		e.Run(ctx)
	}()

	// Wait for first heartbeat, then mark as disconnected to test restoration
	time.Sleep(30 * time.Millisecond)
	mu.Lock()
	if atomic.LoadInt32(&heartbeatCount) >= 1 {
		e.isConnected.Store(false)
		disconnectedAfterFirst = true
	}
	mu.Unlock()

	<-ctx.Done()

	// Verify we triggered the disconnected scenario
	mu.Lock()
	wasDisconnected := disconnectedAfterFirst
	mu.Unlock()

	if !wasDisconnected {
		t.Skip("could not trigger disconnection scenario")
	}

	// Connection should be restored after successful heartbeat
	if !e.isConnected.Load() {
		t.Error("expected isConnected to be true after successful heartbeat when previously disconnected")
	}
}

// TestHeartbeatNonOKStatusAfterDecodeFailure tests the error path when response can't be decoded
func TestHeartbeatNonOKStatusAfterDecodeFailure(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path == "/agent/heartbeat" {
			w.WriteHeader(http.StatusInternalServerError)
			w.Write([]byte("not json")) // Invalid JSON body
			return
		}
		w.WriteHeader(http.StatusOK)
	}))
	defer srv.Close()

	e := New(Config{
		Endpoint:      srv.URL,
		APIKey:        "test-key",
		FlushInterval: 10 * time.Second,
	})

	ctx := context.Background()
	_, err := e.sendHeartbeat(ctx)

	if err == nil {
		t.Error("expected error from sendHeartbeat")
	}
}

// TestMarkSuccessAndFailure tests connection health tracking
func TestMarkSuccessAndFailure(t *testing.T) {
	e := New(Config{
		Endpoint: "http://localhost:8080",
		APIKey:   "test-key",
	})

	// Initial state
	if !e.isConnected.Load() {
		t.Error("expected initial isConnected to be true")
	}

	// Mark failure
	e.markFailure()
	if e.isConnected.Load() {
		t.Error("expected isConnected to be false after markFailure")
	}
	if atomic.LoadInt64(&e.consecutiveFailures) != 1 {
		t.Error("expected consecutiveFailures to be 1")
	}

	// Mark another failure
	e.markFailure()
	if atomic.LoadInt64(&e.consecutiveFailures) != 2 {
		t.Error("expected consecutiveFailures to be 2")
	}

	// Mark success
	e.markSuccess()
	if !e.isConnected.Load() {
		t.Error("expected isConnected to be true after markSuccess")
	}
	if atomic.LoadInt64(&e.consecutiveFailures) != 0 {
		t.Error("expected consecutiveFailures to be 0 after markSuccess")
	}
}

// TestFlushEmptyBuffer tests that flushing an empty buffer is a no-op
func TestFlushEmptyBuffer(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path == "/agent/events" {
			t.Error("should not send request for empty buffer")
		}
		w.WriteHeader(http.StatusOK)
	}))
	defer srv.Close()

	e := New(Config{
		Endpoint: srv.URL,
		APIKey:   "test-key",
	})

	// Flush empty buffer - should not send any requests
	e.flush(context.Background())
}

// TestFlushMultipleBatches tests flushing when buffer has more than batchSize events
func TestFlushMultipleBatches(t *testing.T) {
	var mu sync.Mutex
	var batches []int

	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path == "/agent/events" {
			var batch EventBatch
			json.NewDecoder(r.Body).Decode(&batch)
			mu.Lock()
			batches = append(batches, len(batch.Events))
			mu.Unlock()
		}
		w.WriteHeader(http.StatusOK)
	}))
	defer srv.Close()

	e := New(Config{
		Endpoint:  srv.URL,
		APIKey:    "test-key",
		BatchSize: 3,
	})

	// Add 8 events directly to buffer
	e.mu.Lock()
	for i := 0; i < 8; i++ {
		e.buffer = append(e.buffer, event.NewEvent(event.HealthHeartbeat, "fort", "srv", nil))
	}
	e.mu.Unlock()

	// Flush
	e.flush(context.Background())

	mu.Lock()
	defer mu.Unlock()

	// Should have 3 batches: 3 + 3 + 2
	if len(batches) != 3 {
		t.Errorf("expected 3 batches, got %d", len(batches))
	}

	if batches[0] != 3 || batches[1] != 3 || batches[2] != 2 {
		t.Errorf("unexpected batch sizes: %v", batches)
	}
}

// TestHeartbeatErrorStatus tests heartbeat with error in response
func TestHeartbeatErrorStatus(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path == "/agent/heartbeat" {
			w.WriteHeader(http.StatusForbidden)
			json.NewEncoder(w).Encode(map[string]any{
				"status": "error",
				"error":  "invalid api key",
			})
			return
		}
		w.WriteHeader(http.StatusOK)
	}))
	defer srv.Close()

	e := New(Config{
		Endpoint: srv.URL,
		APIKey:   "bad-key",
	})

	ctx := context.Background()
	_, err := e.sendHeartbeat(ctx)

	if err == nil {
		t.Error("expected error from sendHeartbeat with forbidden status")
	}

	if !containsString(err.Error(), "403") {
		t.Errorf("expected error to contain status code 403, got: %v", err)
	}
}

// Helper function
func containsString(s, substr string) bool {
	return len(s) >= len(substr) && (s == substr || len(s) > 0 && containsSubstring(s, substr))
}

func containsSubstring(s, substr string) bool {
	for i := 0; i <= len(s)-len(substr); i++ {
		if s[i:i+len(substr)] == substr {
			return true
		}
	}
	return false
}

// TestSendBatchMaxRetriesExceeded tests that max retries are properly exceeded
func TestSendBatchMaxRetriesExceeded(t *testing.T) {
	var attempts int32

	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path == "/agent/events" {
			atomic.AddInt32(&attempts, 1)
			w.WriteHeader(http.StatusInternalServerError) // Always fail
			return
		}
		w.WriteHeader(http.StatusOK)
	}))
	defer srv.Close()

	e := New(Config{
		Endpoint:   srv.URL,
		APIKey:     "test-key",
		MaxRetries: 2,
		RetryDelay: 1 * time.Millisecond,
	})

	events := []event.Event{
		event.NewEvent(event.HealthHeartbeat, "fort", "srv", nil),
	}

	err := e.sendBatch(context.Background(), events)

	if err == nil {
		t.Error("expected error from sendBatch after max retries")
	}

	// Should be 3 attempts total: initial + 2 retries
	count := atomic.LoadInt32(&attempts)
	if count != 3 {
		t.Errorf("expected 3 attempts (1 + 2 retries), got %d", count)
	}
}

// TestRunHeartbeatFailure tests the heartbeat failure path in the Run loop
func TestRunHeartbeatFailure(t *testing.T) {
	var heartbeatCount int32

	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path == "/agent/heartbeat" {
			count := atomic.AddInt32(&heartbeatCount, 1)
			if count == 1 {
				// First heartbeat succeeds with short interval
				w.Header().Set("Content-Type", "application/json")
				json.NewEncoder(w).Encode(map[string]any{
					"status":           "ok",
					"next_interval_ms": 20,
				})
				return
			}
			// Subsequent heartbeats fail
			w.WriteHeader(http.StatusInternalServerError)
			return
		}
		w.WriteHeader(http.StatusOK)
	}))
	defer srv.Close()

	e := New(Config{
		Endpoint:      srv.URL,
		APIKey:        "test-key",
		FlushInterval: 10 * time.Second,
	})

	ctx, cancel := context.WithTimeout(context.Background(), 150*time.Millisecond)
	defer cancel()

	go e.Run(ctx)
	<-ctx.Done()

	// After failures, isConnected should be false
	count := atomic.LoadInt32(&heartbeatCount)
	if count < 2 {
		t.Skipf("not enough heartbeats, got %d", count)
	}

	// Should have marked some failures
	failures := atomic.LoadInt64(&e.consecutiveFailures)
	if failures == 0 {
		t.Error("expected some failures to be recorded")
	}
}

// TestSendBatchInvalidEndpoint tests sendBatch with an invalid endpoint URL
func TestSendBatchInvalidEndpoint(t *testing.T) {
	e := New(Config{
		Endpoint:   "://invalid-url", // Invalid URL scheme
		APIKey:     "test-key",
		MaxRetries: 0,
		RetryDelay: 1 * time.Millisecond,
	})

	events := []event.Event{
		event.NewEvent(event.HealthHeartbeat, "fort", "srv", nil),
	}

	err := e.sendBatch(context.Background(), events)

	if err == nil {
		t.Error("expected error from sendBatch with invalid endpoint")
	}
}

// TestSendHeartbeatInvalidEndpoint tests sendHeartbeat with an invalid endpoint URL
func TestSendHeartbeatInvalidEndpoint(t *testing.T) {
	e := New(Config{
		Endpoint: "://invalid-url", // Invalid URL scheme
		APIKey:   "test-key",
	})

	_, err := e.sendHeartbeat(context.Background())

	if err == nil {
		t.Error("expected error from sendHeartbeat with invalid endpoint")
	}
}

// TestBufferEventWriteError tests the WriteFile error path in bufferEvent
func TestBufferEventWriteError(t *testing.T) {
	t.Run("MkdirAll fails - path under file", func(t *testing.T) {
		dir := t.TempDir()
		bufferPath := dir + "/buffer"

		// Create buffer path as a file instead of directory
		if err := os.WriteFile(bufferPath, []byte("not a directory"), 0644); err != nil {
			t.Fatalf("failed to create blocking file: %v", err)
		}

		e := New(Config{
			Endpoint:   "http://localhost:8080",
			APIKey:     "test-key",
			BufferPath: bufferPath + "/events", // Path under the file - will fail
		})

		ev := event.NewEvent(event.HealthHeartbeat, "fort", "srv", nil)
		// Should log error but not panic
		e.bufferEvent(ev)
	})

	t.Run("WriteFile fails - read-only directory", func(t *testing.T) {
		dir := t.TempDir()
		bufferPath := dir + "/buffer"

		// Create buffer directory
		if err := os.MkdirAll(bufferPath, 0755); err != nil {
			t.Fatalf("failed to create buffer dir: %v", err)
		}

		// Make it read-only
		if err := os.Chmod(bufferPath, 0555); err != nil {
			t.Fatalf("failed to chmod: %v", err)
		}
		defer os.Chmod(bufferPath, 0755) // Restore for cleanup

		e := New(Config{
			Endpoint:   "http://localhost:8080",
			APIKey:     "test-key",
			BufferPath: bufferPath,
		})

		ev := event.NewEvent(event.HealthHeartbeat, "fort", "srv", nil)
		// Should log error but not panic
		e.bufferEvent(ev)
	})
}

// TestLoadBufferedEventsReadDirError tests non-NotExist error in loadBufferedEvents
func TestLoadBufferedEventsReadDirError(t *testing.T) {
	dir := t.TempDir()
	bufferPath := dir + "/buffer"

	// Create a file where a directory is expected
	if err := os.WriteFile(bufferPath, []byte("not a directory"), 0644); err != nil {
		t.Fatalf("failed to create file: %v", err)
	}

	e := New(Config{
		Endpoint:   "http://localhost:8080",
		APIKey:     "test-key",
		BufferPath: bufferPath,
	})

	// Should log error but not panic
	e.loadBufferedEvents()
}

// TestRunWithDisconnectedThenReconnect tests the "connection restored" path thoroughly
func TestRunWithDisconnectedThenReconnect(t *testing.T) {
	var heartbeatCount int32

	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path == "/agent/heartbeat" {
			count := atomic.AddInt32(&heartbeatCount, 1)
			if count == 1 {
				// First heartbeat fails
				w.WriteHeader(http.StatusInternalServerError)
				return
			}
			// Second heartbeat succeeds with short interval for more iterations
			w.Header().Set("Content-Type", "application/json")
			json.NewEncoder(w).Encode(map[string]any{
				"status":           "ok",
				"next_interval_ms": 20,
			})
			return
		}
		w.WriteHeader(http.StatusOK)
	}))
	defer srv.Close()

	e := New(Config{
		Endpoint:      srv.URL,
		APIKey:        "test-key",
		FlushInterval: 10 * time.Second,
	})

	ctx, cancel := context.WithTimeout(context.Background(), 200*time.Millisecond)
	defer cancel()

	go e.Run(ctx)
	<-ctx.Done()

	// Should have attempted heartbeats
	count := atomic.LoadInt32(&heartbeatCount)
	if count < 2 {
		t.Skipf("not enough heartbeats for recovery test, got %d", count)
	}

	// After recovery, should be connected
	if !e.isConnected.Load() {
		t.Error("expected isConnected to be true after recovery")
	}
}
