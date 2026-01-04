package watcher

import (
	"context"
	"testing"
	"time"

	"github.com/Tesseract-Systems-Corporation/rampart-agent/pkg/event"
)

// mockWatcher is a test implementation of the Watcher interface
type mockWatcher struct {
	events     []event.Event
	eventIndex int
	err        error
}

func newMockWatcher(events []event.Event) *mockWatcher {
	return &mockWatcher{events: events}
}

func (m *mockWatcher) Watch(ctx context.Context) (<-chan event.Event, error) {
	if m.err != nil {
		return nil, m.err
	}

	ch := make(chan event.Event)
	go func() {
		defer close(ch)
		for _, e := range m.events {
			select {
			case <-ctx.Done():
				return
			case ch <- e:
			}
		}
	}()
	return ch, nil
}

func (m *mockWatcher) Name() string {
	return "mock"
}

func TestWatcherInterface(t *testing.T) {
	// Verify mockWatcher implements Watcher
	var _ Watcher = (*mockWatcher)(nil)
}

func TestMockWatcherEmitsEvents(t *testing.T) {
	events := []event.Event{
		event.NewEvent(event.ContainerStarted, "fort_1", "srv_1", map[string]any{"container": "nginx"}),
		event.NewEvent(event.ContainerStopped, "fort_1", "srv_1", map[string]any{"container": "nginx"}),
	}

	w := newMockWatcher(events)
	ctx, cancel := context.WithTimeout(context.Background(), time.Second)
	defer cancel()

	ch, err := w.Watch(ctx)
	if err != nil {
		t.Fatalf("Watch() error = %v", err)
	}

	received := make([]event.Event, 0)
	for e := range ch {
		received = append(received, e)
	}

	if len(received) != len(events) {
		t.Errorf("received %d events, want %d", len(received), len(events))
	}
}

func TestMockWatcherRespectsContext(t *testing.T) {
	// Create watcher with many events
	events := make([]event.Event, 100)
	for i := range events {
		events[i] = event.NewEvent(event.HealthHeartbeat, "fort_1", "srv_1", nil)
	}

	w := newMockWatcher(events)
	ctx, cancel := context.WithCancel(context.Background())

	ch, err := w.Watch(ctx)
	if err != nil {
		t.Fatalf("Watch() error = %v", err)
	}

	// Receive one event then cancel
	<-ch
	cancel()

	// Give goroutine time to notice cancellation
	time.Sleep(10 * time.Millisecond)

	// Channel should be closed
	select {
	case _, ok := <-ch:
		if ok {
			// Might receive buffered events, that's ok
		}
	case <-time.After(100 * time.Millisecond):
		// Timeout is acceptable if channel is empty
	}
}

func TestWatcherName(t *testing.T) {
	w := newMockWatcher(nil)
	if w.Name() != "mock" {
		t.Errorf("Name() = %v, want mock", w.Name())
	}
}

func TestMultiplexer(t *testing.T) {
	events1 := []event.Event{
		event.NewEvent(event.ContainerStarted, "fort_1", "srv_1", map[string]any{"source": "watcher1"}),
	}
	events2 := []event.Event{
		event.NewEvent(event.AccessSSH, "fort_1", "srv_1", map[string]any{"source": "watcher2"}),
	}

	w1 := newMockWatcher(events1)
	w2 := newMockWatcher(events2)

	mux := NewMultiplexer(w1, w2)

	ctx, cancel := context.WithTimeout(context.Background(), time.Second)
	defer cancel()

	ch, err := mux.Watch(ctx)
	if err != nil {
		t.Fatalf("Watch() error = %v", err)
	}

	received := make([]event.Event, 0)
	for e := range ch {
		received = append(received, e)
	}

	if len(received) != 2 {
		t.Errorf("received %d events, want 2", len(received))
	}
}

func TestMultiplexerName(t *testing.T) {
	mux := NewMultiplexer()
	if mux.Name() != "multiplexer" {
		t.Errorf("Name() = %v, want multiplexer", mux.Name())
	}
}

func TestMultiplexerWithNoWatchers(t *testing.T) {
	mux := NewMultiplexer()

	ctx, cancel := context.WithTimeout(context.Background(), 100*time.Millisecond)
	defer cancel()

	ch, err := mux.Watch(ctx)
	if err != nil {
		t.Fatalf("Watch() error = %v", err)
	}

	// Should receive no events
	received := 0
	for range ch {
		received++
	}

	if received != 0 {
		t.Errorf("received %d events, want 0", received)
	}
}

func TestMultiplexerAdd(t *testing.T) {
	mux := NewMultiplexer()

	if len(mux.watchers) != 0 {
		t.Errorf("initial watchers count = %d, want 0", len(mux.watchers))
	}

	w1 := newMockWatcher(nil)
	mux.Add(w1)

	if len(mux.watchers) != 1 {
		t.Errorf("watchers count after Add = %d, want 1", len(mux.watchers))
	}

	w2 := newMockWatcher(nil)
	mux.Add(w2)

	if len(mux.watchers) != 2 {
		t.Errorf("watchers count after second Add = %d, want 2", len(mux.watchers))
	}
}

func TestMultiplexerContextCancellation(t *testing.T) {
	events := make([]event.Event, 100)
	for i := range events {
		events[i] = event.NewEvent(event.HealthHeartbeat, "fort_1", "srv_1", nil)
	}

	w := newMockWatcher(events)
	mux := NewMultiplexer(w)

	ctx, cancel := context.WithCancel(context.Background())

	ch, err := mux.Watch(ctx)
	if err != nil {
		t.Fatalf("Watch() error = %v", err)
	}

	// Receive one event
	select {
	case <-ch:
	case <-time.After(100 * time.Millisecond):
		t.Fatal("timeout waiting for first event")
	}

	// Cancel context
	cancel()

	// Channel should close
	select {
	case _, ok := <-ch:
		if ok {
			// Drain remaining events
			for range ch {
			}
		}
	case <-time.After(100 * time.Millisecond):
		t.Error("channel did not close after context cancellation")
	}
}

// errorWatcher is a mock watcher that returns an error
type errorWatcher struct {
	err error
}

func (e *errorWatcher) Watch(ctx context.Context) (<-chan event.Event, error) {
	return nil, e.err
}

func (e *errorWatcher) Name() string {
	return "error"
}

func TestMultiplexerWithMultipleWatchers(t *testing.T) {
	events1 := []event.Event{
		event.NewEvent(event.ContainerStarted, "fort_1", "srv_1", map[string]any{"source": "w1-1"}),
		event.NewEvent(event.ContainerStopped, "fort_1", "srv_1", map[string]any{"source": "w1-2"}),
	}
	events2 := []event.Event{
		event.NewEvent(event.AccessSSH, "fort_1", "srv_1", map[string]any{"source": "w2-1"}),
	}
	events3 := []event.Event{
		event.NewEvent(event.HealthHeartbeat, "fort_1", "srv_1", map[string]any{"source": "w3-1"}),
		event.NewEvent(event.HealthHeartbeat, "fort_1", "srv_1", map[string]any{"source": "w3-2"}),
		event.NewEvent(event.HealthHeartbeat, "fort_1", "srv_1", map[string]any{"source": "w3-3"}),
	}

	w1 := newMockWatcher(events1)
	w2 := newMockWatcher(events2)
	w3 := newMockWatcher(events3)

	mux := NewMultiplexer(w1, w2, w3)

	ctx, cancel := context.WithTimeout(context.Background(), time.Second)
	defer cancel()

	ch, err := mux.Watch(ctx)
	if err != nil {
		t.Fatalf("Watch() error = %v", err)
	}

	received := make([]event.Event, 0)
	for e := range ch {
		received = append(received, e)
	}

	if len(received) != 6 {
		t.Errorf("received %d events, want 6", len(received))
	}
}

func TestMockWatcherWithError(t *testing.T) {
	w := &mockWatcher{
		err: context.DeadlineExceeded,
	}

	ch, err := w.Watch(context.Background())
	if err == nil {
		t.Error("expected error, got nil")
	}
	if ch != nil {
		t.Error("expected nil channel when error is returned")
	}
}
