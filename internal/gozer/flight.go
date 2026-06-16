package gozer

import "sync"

type flightResult struct {
	body      []byte
	fromCache bool
}

type flightCall struct {
	done       chan struct{}
	result     flightResult
	panicValue any
	panicked   bool
}

// flightGroup coalesces simultaneous cache misses for one message. It is kept
// local to gozer so the request hot path does not need another dependency.
type flightGroup struct {
	mu sync.Mutex
	m  map[string]*flightCall
}

func (g *flightGroup) Do(key string, fn func() flightResult) (flightResult, bool) {
	g.mu.Lock()
	if call := g.m[key]; call != nil {
		g.mu.Unlock()
		<-call.done
		if call.panicked {
			panic(call.panicValue)
		}
		return call.result, true
	}
	if g.m == nil {
		g.m = make(map[string]*flightCall)
	}
	call := &flightCall{done: make(chan struct{})}
	g.m[key] = call
	g.mu.Unlock()

	defer func() {
		if rec := recover(); rec != nil {
			call.panicValue = rec
			call.panicked = true
		}
		g.mu.Lock()
		delete(g.m, key)
		close(call.done)
		g.mu.Unlock()
		if call.panicked {
			panic(call.panicValue)
		}
	}()
	call.result = fn()
	return call.result, false
}
