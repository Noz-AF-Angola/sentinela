package auth

import (
	"crypto/rand"
	"encoding/base64"
	"sync"
	"time"
)

// Session is a logged-in browser. Sessions live in memory only: restarting
// Sentinela logs everybody out, which is acceptable for an admin tool.
type Session struct {
	ID      string
	User    string
	Role    Role
	CSRF    string
	Proxy   bool // created from a trusted proxy header
	Expires time.Time
	Flashes []Flash
}

// Flash is a one-shot message shown on the next page.
type Flash struct {
	Kind string // ok | error | info
	Text string
}

// Store keeps sessions in memory.
type Store struct {
	mu       sync.Mutex
	sessions map[string]*Session
	ttl      time.Duration
	now      func() time.Time
}

// NewStore creates an empty store whose sessions expire after ttl.
func NewStore(ttl time.Duration) *Store {
	return &Store{sessions: map[string]*Session{}, ttl: ttl, now: time.Now}
}

func randomToken() string {
	b := make([]byte, 32)
	if _, err := rand.Read(b); err != nil {
		panic("crypto/rand failed: " + err.Error())
	}
	return base64.RawURLEncoding.EncodeToString(b)
}

// Create starts a new session.
func (s *Store) Create(user string, role Role, proxy bool) *Session {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.gcLocked()
	sess := &Session{
		ID: randomToken(), User: user, Role: role, CSRF: randomToken(),
		Proxy: proxy, Expires: s.now().Add(s.ttl),
	}
	s.sessions[sess.ID] = sess
	return sess
}

// Get returns a copy of a live session, or nil.
func (s *Store) Get(id string) *Session {
	if id == "" {
		return nil
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	sess, ok := s.sessions[id]
	if !ok {
		return nil
	}
	if s.now().After(sess.Expires) {
		delete(s.sessions, id)
		return nil
	}
	cp := *sess
	cp.Flashes = append([]Flash(nil), sess.Flashes...)
	return &cp
}

// AddFlash queues a message for the next page view of this session.
func (s *Store) AddFlash(id, kind, text string) {
	s.mu.Lock()
	defer s.mu.Unlock()
	if sess, ok := s.sessions[id]; ok && len(sess.Flashes) < 10 {
		sess.Flashes = append(sess.Flashes, Flash{Kind: kind, Text: text})
	}
}

// PopFlashes returns and clears the queued messages.
func (s *Store) PopFlashes(id string) []Flash {
	s.mu.Lock()
	defer s.mu.Unlock()
	sess, ok := s.sessions[id]
	if !ok {
		return nil
	}
	f := sess.Flashes
	sess.Flashes = nil
	return f
}

// Delete ends a session.
func (s *Store) Delete(id string) {
	s.mu.Lock()
	defer s.mu.Unlock()
	delete(s.sessions, id)
}

func (s *Store) gcLocked() {
	now := s.now()
	for id, sess := range s.sessions {
		if now.After(sess.Expires) {
			delete(s.sessions, id)
		}
	}
}
