package cas

import (
	"context"
	"net/http"
	"net/url"
	"strings"
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
			// Build the service URL for validation (current request URL without ticket)
			serviceURL := buildServiceURL(r)
			user, err := m.client.ValidateTicketWithService(ticket, serviceURL)
			if err != nil {
				// Ticket validation failed, redirect to login with current URL
				redirectToLoginWithService(w, r, m.client, serviceURL)
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
			cleanURL := RemoveTicketFromURL(r.URL)
			http.Redirect(w, r, cleanURL, http.StatusFound)
			return
		}

		// No session and no ticket, redirect to CAS login with current URL as service
		serviceURL := buildServiceURL(r)
		redirectToLoginWithService(w, r, m.client, serviceURL)
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

// buildServiceURL builds the service URL from the current request
func buildServiceURL(r *http.Request) string {
	// Determine scheme
	scheme := "http"
	if r.TLS != nil {
		scheme = "https"
	}
	// Check X-Forwarded-Proto header (for reverse proxy)
	if proto := r.Header.Get("X-Forwarded-Proto"); proto != "" {
		scheme = proto
	}

	// Build URL without ticket parameter
	u := &url.URL{
		Scheme:   scheme,
		Host:     r.Host,
		Path:     r.URL.Path,
		RawQuery: removeTicketParam(r.URL.RawQuery),
	}

	return u.String()
}

// redirectToLoginWithService redirects to CAS login with specific service URL
func redirectToLoginWithService(w http.ResponseWriter, r *http.Request, client *Client, serviceURL string) {
	loginURL := client.GetLoginURLForService(serviceURL)
	http.Redirect(w, r, loginURL, http.StatusFound)
}

// RemoveTicketFromURL removes the ticket parameter from URL using proper URL parsing
func RemoveTicketFromURL(u *url.URL) string {
	// Create a copy to avoid modifying the original
	result := &url.URL{
		Scheme:   u.Scheme,
		Host:     u.Host,
		Path:     u.Path,
		Fragment: u.Fragment,
	}

	// Remove ticket from query parameters
	result.RawQuery = removeTicketParam(u.RawQuery)

	return result.String()
}

// removeTicketParam removes the ticket parameter from query string
func removeTicketParam(rawQuery string) string {
	if rawQuery == "" {
		return ""
	}

	values, err := url.ParseQuery(rawQuery)
	if err != nil {
		return rawQuery
	}

	values.Del("ticket")

	return values.Encode()
}

// removeTicketFromURL is kept for backward compatibility (deprecated)
// Deprecated: Use RemoveTicketFromURL instead
func removeTicketFromURL(rawURL string) string {
	u, err := url.Parse(rawURL)
	if err != nil {
		return rawURL
	}

	// Remove ticket parameter
	q := u.Query()
	q.Del("ticket")
	u.RawQuery = q.Encode()

	// Clean up empty query string
	result := u.String()
	result = strings.TrimSuffix(result, "?")

	return result
}
