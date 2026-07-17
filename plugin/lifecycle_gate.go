package plugin

import (
	"context"
	"errors"
	"sync"
)

// lifecycleGate admits concurrent lifecycle operations while making shutdown
// admission context-aware. Once beginClose is called, no new operation can
// enter; an already running operation is allowed to finish or be bounded by
// the caller's shutdown deadline.
type lifecycleGate struct {
	mu      sync.Mutex
	closing bool
	active  int
	idle    chan struct{}
}

func newLifecycleGate() *lifecycleGate {
	return &lifecycleGate{}
}

func (g *lifecycleGate) enter(ctx context.Context) (func(), error) {
	if g == nil {
		return nil, errors.New("plugin lifecycle gate is unavailable")
	}
	if ctx == nil {
		ctx = context.Background()
	}
	if err := ctx.Err(); err != nil {
		return nil, err
	}
	g.mu.Lock()
	defer g.mu.Unlock()
	if g.closing {
		return nil, errors.New("plugin supervisor is closing")
	}
	if g.active == 0 {
		g.idle = make(chan struct{})
	}
	g.active++
	var once sync.Once
	return func() {
		once.Do(func() { g.leave() })
	}, nil
}

func (g *lifecycleGate) leave() {
	g.mu.Lock()
	defer g.mu.Unlock()
	if g.active == 0 {
		return
	}
	g.active--
	if g.active == 0 && g.idle != nil {
		close(g.idle)
		g.idle = nil
	}
}

func (g *lifecycleGate) beginClose(ctx context.Context) error {
	if g == nil {
		return errors.New("plugin lifecycle gate is unavailable")
	}
	if ctx == nil {
		ctx = context.Background()
	}
	g.mu.Lock()
	g.closing = true
	if g.active == 0 {
		g.mu.Unlock()
		return nil
	}
	idle := g.idle
	g.mu.Unlock()
	select {
	case <-idle:
		return nil
	case <-ctx.Done():
		return ctx.Err()
	}
}
