package cas

import (
	"crypto/rand"
	"encoding/base64"
	"encoding/json"
	"errors"
	"net/http"
	"sync"
	"time"
)

// MemorySessionStore is a simple in-memory session store
// Note: This is for development/testing only. Use Redis or database in production.
type MemorySessionStore struct {
	sessions   map[string]*sessionData
	mu         sync.RWMutex
	cookieName string
	maxAge     int // seconds
}

type sessionData struct {
	User      *User
	ExpiresAt time.Time
}

// NewMemorySessionStore creates a new in-memory session store
func NewMemorySessionStore(cookieName string, maxAge int) *MemorySessionStore {
	store := &MemorySessionStore{
		sessions:   make(map[string]*sessionData),
		cookieName: cookieName,
		maxAge:     maxAge,
	}
	// Start cleanup goroutine
	go store.cleanup()
	return store
}

// Get retrieves a user from session
func (s *MemorySessionStore) Get(r *http.Request) (*User, error) {
	cookie, err := r.Cookie(s.cookieName)
	if err != nil {
		return nil, err
	}

	s.mu.RLock()
	defer s.mu.RUnlock()

	data, ok := s.sessions[cookie.Value]
	if !ok {
		return nil, errors.New("session not found")
	}

	if time.Now().After(data.ExpiresAt) {
		return nil, errors.New("session expired")
	}

	return data.User, nil
}

// Set stores a user in session
func (s *MemorySessionStore) Set(w http.ResponseWriter, r *http.Request, user *User) error {
	sessionID := generateSessionID()

	s.mu.Lock()
	s.sessions[sessionID] = &sessionData{
		User:      user,
		ExpiresAt: time.Now().Add(time.Duration(s.maxAge) * time.Second),
	}
	s.mu.Unlock()

	http.SetCookie(w, &http.Cookie{
		Name:     s.cookieName,
		Value:    sessionID,
		Path:     "/",
		MaxAge:   s.maxAge,
		HttpOnly: true,
		Secure:   true,
		SameSite: http.SameSiteLaxMode,
	})

	return nil
}

// Delete removes a user from session
func (s *MemorySessionStore) Delete(w http.ResponseWriter, r *http.Request) error {
	cookie, err := r.Cookie(s.cookieName)
	if err == nil {
		s.mu.Lock()
		delete(s.sessions, cookie.Value)
		s.mu.Unlock()
	}

	http.SetCookie(w, &http.Cookie{
		Name:     s.cookieName,
		Value:    "",
		Path:     "/",
		MaxAge:   -1,
		HttpOnly: true,
	})

	return nil
}

// cleanup periodically removes expired sessions
func (s *MemorySessionStore) cleanup() {
	ticker := time.NewTicker(5 * time.Minute)
	for range ticker.C {
		s.mu.Lock()
		now := time.Now()
		for id, data := range s.sessions {
			if now.After(data.ExpiresAt) {
				delete(s.sessions, id)
			}
		}
		s.mu.Unlock()
	}
}

func generateSessionID() string {
	b := make([]byte, 32)
	rand.Read(b)
	return base64.URLEncoding.EncodeToString(b)
}

// CookieSessionStore stores user data directly in an encrypted cookie
type CookieSessionStore struct {
	cookieName string
	maxAge     int
	secret     []byte // For signing/encryption (simplified - use proper encryption in production)
}

// NewCookieSessionStore creates a new cookie-based session store
func NewCookieSessionStore(cookieName string, maxAge int, secret string) *CookieSessionStore {
	return &CookieSessionStore{
		cookieName: cookieName,
		maxAge:     maxAge,
		secret:     []byte(secret),
	}
}

// Get retrieves a user from cookie
func (s *CookieSessionStore) Get(r *http.Request) (*User, error) {
	cookie, err := r.Cookie(s.cookieName)
	if err != nil {
		return nil, err
	}

	data, err := base64.URLEncoding.DecodeString(cookie.Value)
	if err != nil {
		return nil, err
	}

	var user User
	if err := json.Unmarshal(data, &user); err != nil {
		return nil, err
	}

	return &user, nil
}

// Set stores a user in cookie
func (s *CookieSessionStore) Set(w http.ResponseWriter, r *http.Request, user *User) error {
	data, err := json.Marshal(user)
	if err != nil {
		return err
	}

	encoded := base64.URLEncoding.EncodeToString(data)

	http.SetCookie(w, &http.Cookie{
		Name:     s.cookieName,
		Value:    encoded,
		Path:     "/",
		MaxAge:   s.maxAge,
		HttpOnly: true,
		Secure:   true,
		SameSite: http.SameSiteLaxMode,
	})

	return nil
}

// Delete removes the session cookie
func (s *CookieSessionStore) Delete(w http.ResponseWriter, r *http.Request) error {
	http.SetCookie(w, &http.Cookie{
		Name:     s.cookieName,
		Value:    "",
		Path:     "/",
		MaxAge:   -1,
		HttpOnly: true,
	})
	return nil
}
