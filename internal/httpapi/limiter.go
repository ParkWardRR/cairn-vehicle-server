package httpapi

import (
	"sync"
	"time"
)

// Limiter is a per-device token bucket.
//
// The purpose is containment rather than fairness: one device stuck in a retry
// loop — a plausible outcome of a firmware bug in a parked car — must not be
// able to saturate the server for the others. Buckets are generous, because a
// device returning home with a week of backlog is legitimate traffic.
type Limiter struct {
	capacity   float64
	refillRate float64 // tokens per second

	mu      sync.Mutex
	buckets map[string]*bucket
	now     func() time.Time
}

type bucket struct {
	tokens   float64
	lastSeen time.Time
}

// NewLimiter creates a limiter allowing bursts up to capacity and sustained
// traffic at refillPerSecond.
func NewLimiter(capacity, refillPerSecond float64) *Limiter {
	return &Limiter{
		capacity:   capacity,
		refillRate: refillPerSecond,
		buckets:    make(map[string]*bucket),
		now:        time.Now,
	}
}

// Allow consumes a token for key, reporting whether the request may proceed.
func (l *Limiter) Allow(key string) bool {
	l.mu.Lock()
	defer l.mu.Unlock()

	now := l.now()

	b, ok := l.buckets[key]
	if !ok {
		l.buckets[key] = &bucket{tokens: l.capacity - 1, lastSeen: now}
		return true
	}

	elapsed := now.Sub(b.lastSeen).Seconds()
	b.tokens += elapsed * l.refillRate
	if b.tokens > l.capacity {
		b.tokens = l.capacity
	}
	b.lastSeen = now

	if b.tokens < 1 {
		return false
	}
	b.tokens--
	return true
}

// Sweep discards buckets untouched for longer than idle, so the map does not
// grow without bound as devices come and go.
func (l *Limiter) Sweep(idle time.Duration) int {
	l.mu.Lock()
	defer l.mu.Unlock()

	cutoff := l.now().Add(-idle)
	removed := 0
	for key, b := range l.buckets {
		if b.lastSeen.Before(cutoff) {
			delete(l.buckets, key)
			removed++
		}
	}
	return removed
}

// Tracked returns how many buckets are held, for diagnostics.
func (l *Limiter) Tracked() int {
	l.mu.Lock()
	defer l.mu.Unlock()
	return len(l.buckets)
}
