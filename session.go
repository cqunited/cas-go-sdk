package cas

import (
	"crypto/hmac"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
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
	data, ok := s.sessions[cookie.Value]
	s.mu.RUnlock()

	if !ok {
		return nil, errors.New("session not found")
	}

	if time.Now().After(data.ExpiresAt) {
		// Clean up expired session
		s.mu.Lock()
		delete(s.sessions, cookie.Value)
		s.mu.Unlock()
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
		Secure:   r.TLS != nil || r.Header.Get("X-Forwarded-Proto") == "https",
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

// CookieSessionStore stores user data in a signed cookie
type CookieSessionStore struct {
	cookieName string
	maxAge     int
	secret     []byte
}

// NewCookieSessionStore creates a new cookie-based session store
// The secret should be at least 32 bytes for security
func NewCookieSessionStore(cookieName string, maxAge int, secret string) *CookieSessionStore {
	return &CookieSessionStore{
		cookieName: cookieName,
		maxAge:     maxAge,
		secret:     []byte(secret),
	}
}

// cookieData wraps user data with expiration for cookie storage
type cookieData struct {
	User      *User     `json:"user"`
	ExpiresAt time.Time `json:"exp"`
}

// Get retrieves a user from cookie
func (s *CookieSessionStore) Get(r *http.Request) (*User, error) {
	cookie, err := r.Cookie(s.cookieName)
	if err != nil {
		return nil, err
	}

	// Decode and verify the cookie value
	data, err := s.decodeCookie(cookie.Value)
	if err != nil {
		return nil, err
	}

	// Check expiration
	if time.Now().After(data.ExpiresAt) {
		return nil, errors.New("session expired")
	}

	return data.User, nil
}

// Set stores a user in cookie
func (s *CookieSessionStore) Set(w http.ResponseWriter, r *http.Request, user *User) error {
	data := &cookieData{
		User:      user,
		ExpiresAt: time.Now().Add(time.Duration(s.maxAge) * time.Second),
	}

	encoded, err := s.encodeCookie(data)
	if err != nil {
		return err
	}

	http.SetCookie(w, &http.Cookie{
		Name:     s.cookieName,
		Value:    encoded,
		Path:     "/",
		MaxAge:   s.maxAge,
		HttpOnly: true,
		Secure:   r.TLS != nil || r.Header.Get("X-Forwarded-Proto") == "https",
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

// encodeCookie encodes and signs the cookie data
func (s *CookieSessionStore) encodeCookie(data *cookieData) (string, error) {
	jsonData, err := json.Marshal(data)
	if err != nil {
		return "", err
	}

	// Create HMAC signature
	mac := hmac.New(sha256.New, s.secret)
	mac.Write(jsonData)
	signature := mac.Sum(nil)

	// Encode: base64(json) + "." + hex(signature)
	encoded := base64.URLEncoding.EncodeToString(jsonData)
	sig := hex.EncodeToString(signature)

	return encoded + "." + sig, nil
}

// decodeCookie decodes and verifies the cookie data
func (s *CookieSessionStore) decodeCookie(value string) (*cookieData, error) {
	// Split into data and signature
	parts := splitCookieValue(value)
	if len(parts) != 2 {
		return nil, errors.New("invalid cookie format")
	}

	encoded, sig := parts[0], parts[1]

	// Decode the data
	jsonData, err := base64.URLEncoding.DecodeString(encoded)
	if err != nil {
		return nil, errors.New("invalid cookie encoding")
	}

	// Verify signature
	signature, err := hex.DecodeString(sig)
	if err != nil {
		return nil, errors.New("invalid signature encoding")
	}

	mac := hmac.New(sha256.New, s.secret)
	mac.Write(jsonData)
	expectedSig := mac.Sum(nil)

	if !hmac.Equal(signature, expectedSig) {
		return nil, errors.New("invalid cookie signature")
	}

	// Unmarshal the data
	var data cookieData
	if err := json.Unmarshal(jsonData, &data); err != nil {
		return nil, err
	}

	return &data, nil
}

// splitCookieValue splits cookie value by "."
func splitCookieValue(value string) []string {
	for i := len(value) - 1; i >= 0; i-- {
		if value[i] == '.' {
			return []string{value[:i], value[i+1:]}
		}
	}
	return []string{value}
}
