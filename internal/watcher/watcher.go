// Package watcher provides interfaces and implementations for monitoring
// system events like Docker containers, SSH access, file drift, and health metrics.
package watcher

import (
	"context"

	"github.com/Tesseract-Systems-Corporation/rampart-agent/pkg/event"
	"golang.org/x/sync/errgroup"
)

// Watcher is the interface for all event watchers.
// Implementations monitor specific aspects of the system and emit events.
type Watcher interface {
	// Watch starts watching and returns a channel of events.
	// The channel is closed when the context is cancelled.
	Watch(ctx context.Context) (<-chan event.Event, error)

	// Name returns the watcher's identifier for logging.
	Name() string
}

// Multiplexer combines multiple watchers into a single event stream.
type Multiplexer struct {
	watchers []Watcher
}

// NewMultiplexer creates a new Multiplexer from the given watchers.
func NewMultiplexer(watchers ...Watcher) *Multiplexer {
	return &Multiplexer{watchers: watchers}
}

// Watch starts all watchers and multiplexes their events into a single channel.
func (m *Multiplexer) Watch(ctx context.Context) (<-chan event.Event, error) {
	out := make(chan event.Event)

	if len(m.watchers) == 0 {
		go func() {
			<-ctx.Done()
			close(out)
		}()
		return out, nil
	}

	g, ctx := errgroup.WithContext(ctx)

	for _, w := range m.watchers {
		w := w // capture for goroutine
		g.Go(func() error {
			ch, err := w.Watch(ctx)
			if err != nil {
				return err
			}

			for e := range ch {
				select {
				case <-ctx.Done():
					return ctx.Err()
				case out <- e:
				}
			}
			return nil
		})
	}

	// Close output channel when all watchers are done
	go func() {
		_ = g.Wait()
		close(out)
	}()

	return out, nil
}

// Name returns "multiplexer" as the watcher name.
func (m *Multiplexer) Name() string {
	return "multiplexer"
}

// Add adds a watcher to the multiplexer.
func (m *Multiplexer) Add(w Watcher) {
	m.watchers = append(m.watchers, w)
}
