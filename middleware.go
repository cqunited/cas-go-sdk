package cas

import (
	"context"
	"net/http"
)

// ContextKey is the type for context keys
type ContextKey string

const (
	// UserContextKey is the context key for storing CAS user
	UserContextKey ContextKey = "cas_user"
)

// Middleware provides HTTP middleware for CAS authentication
type Middleware struct {
	client *Client
	// SessionStore for storing user sessions
	sessionStore SessionStore
	// IgnorePaths are paths that don't require authentication
	IgnorePaths []string
}

// SessionStore interface for session management
type SessionStore interface {
	// Get retrieves a user from session
	Get(r *http.Request) (*User, error)
	// Set stores a user in session
	Set(w http.ResponseWriter, r *http.Request, user *User) error
	// Delete removes a user from session
	Delete(w http.ResponseWriter, r *http.Request) error
}

// NewMiddleware creates a new CAS middleware
func NewMiddleware(client *Client, store SessionStore) *Middleware {
	return &Middleware{
		client:       client,
		sessionStore: store,
		IgnorePaths:  []string{},
	}
}

// Handler wraps an http.Handler with CAS authentication
func (m *Middleware) Handler(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		// Check if path should be ignored
		for _, path := range m.IgnorePaths {
			if r.URL.Path == path {
				next.ServeHTTP(w, r)
				return
			}
		}

		// Check for existing session
		if m.sessionStore != nil {
			if user, err := m.sessionStore.Get(r); err == nil && user != nil {
				ctx := context.WithValue(r.Context(), UserContextKey, user)
				next.ServeHTTP(w, r.WithContext(ctx))
				return
			}
		}

		// Check for CAS ticket in URL
		ticket := GetTicketFromRequest(r)
		if ticket != "" {
			user, err := m.client.ValidateTicket(ticket)
			if err != nil {
				// Ticket validation failed, redirect to login
				m.client.RedirectToLogin(w, r)
				return
			}

			// Store user in session
			if m.sessionStore != nil {
				if err := m.sessionStore.Set(w, r, user); err != nil {
					http.Error(w, "Failed to create session", http.StatusInternalServerError)
					return
				}
			}

			// Remove ticket from URL and redirect
			cleanURL := removeTicketFromURL(r.URL.String())
			http.Redirect(w, r, cleanURL, http.StatusFound)
			return
		}

		// No session and no ticket, redirect to CAS login
		m.client.RedirectToLogin(w, r)
	})
}

// HandlerFunc wraps an http.HandlerFunc with CAS authentication
func (m *Middleware) HandlerFunc(next http.HandlerFunc) http.HandlerFunc {
	return m.Handler(next).ServeHTTP
}

// GetUserFromContext retrieves the CAS user from request context
func GetUserFromContext(ctx context.Context) *User {
	if user, ok := ctx.Value(UserContextKey).(*User); ok {
		return user
	}
	return nil
}

// removeTicketFromURL removes the ticket parameter from URL
func removeTicketFromURL(rawURL string) string {
	// Simple implementation - in production, use proper URL parsing
	if idx := indexOf(rawURL, "ticket="); idx != -1 {
		// Find the start of ticket parameter
		start := idx
		if start > 0 && rawURL[start-1] == '&' {
			start--
		} else if start > 0 && rawURL[start-1] == '?' {
			// Keep the '?' if ticket is the only parameter
		}

		// Find the end of ticket parameter
		end := idx + 7 // len("ticket=")
		for end < len(rawURL) && rawURL[end] != '&' {
			end++
		}
		if end < len(rawURL) && rawURL[end] == '&' {
			end++
		}

		// Remove the ticket parameter
		result := rawURL[:start] + rawURL[end:]
		// Clean up trailing ? or &
		result = trimSuffix(result, "?")
		result = trimSuffix(result, "&")
		return result
	}
	return rawURL
}

func indexOf(s, substr string) int {
	for i := 0; i <= len(s)-len(substr); i++ {
		if s[i:i+len(substr)] == substr {
			return i
		}
	}
	return -1
}

func trimSuffix(s, suffix string) string {
	if len(s) >= len(suffix) && s[len(s)-len(suffix):] == suffix {
		return s[:len(s)-len(suffix)]
	}
	return s
}
