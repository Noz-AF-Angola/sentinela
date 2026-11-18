package auth

import (
	"sync"
	"time"
)

// Limiter counts failed logins per key (client IP, user name) and locks a key
// out for a while once it has failed too often.
type Limiter struct {
	mu      sync.Mutex
	max     int
	window  time.Duration
	entries map[string]*limitEntry
	now     func() time.Time
}

type limitEntry struct {
	failures int
	first    time.Time
}

// NewLimiter allows max failures per key within window.
func NewLimiter(max int, window time.Duration) *Limiter {
	return &Limiter{max: max, window: window, entries: map[string]*limitEntry{}, now: time.Now}
}

// Allowed reports whether key may try again.
func (l *Limiter) Allowed(key string) bool {
	l.mu.Lock()
	defer l.mu.Unlock()
	e, ok := l.entries[key]
	if !ok {
		return true
	}
	if l.now().Sub(e.first) > l.window {
		delete(l.entries, key)
		return true
	}
	return e.failures < l.max
}

// Fail records a failed attempt for key.
func (l *Limiter) Fail(key string) {
	l.mu.Lock()
	defer l.mu.Unlock()
	now := l.now()
	if len(l.entries) > 10000 {
		for k, e := range l.entries {
			if now.Sub(e.first) > l.window {
				delete(l.entries, k)
			}
		}
	}
	e, ok := l.entries[key]
	if !ok || now.Sub(e.first) > l.window {
		l.entries[key] = &limitEntry{failures: 1, first: now}
		return
	}
	e.failures++
}

// Reset forgets key after a successful login.
func (l *Limiter) Reset(key string) {
	l.mu.Lock()
	defer l.mu.Unlock()
	delete(l.entries, key)
}
