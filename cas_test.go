package cas

import (
	"net/http"
	"net/http/httptest"
	"net/url"
	"testing"
)

func TestNewClient(t *testing.T) {
	client := NewClient("https://cas.example.com/cas", "http://localhost:8080")

	if client.CASServerURLPrefix != "https://cas.example.com/cas" {
		t.Errorf("Expected CASServerURLPrefix to be 'https://cas.example.com/cas', got '%s'", client.CASServerURLPrefix)
	}

	if client.ServiceURL != "http://localhost:8080" {
		t.Errorf("Expected ServiceURL to be 'http://localhost:8080', got '%s'", client.ServiceURL)
	}
}

func TestGetLoginURL(t *testing.T) {
	client := NewClient("https://cas.example.com/cas", "http://localhost:8080")

	loginURL := client.GetLoginURL()
	expected := "https://cas.example.com/cas/login?service=http%3A%2F%2Flocalhost%3A8080"

	if loginURL != expected {
		t.Errorf("Expected login URL to be '%s', got '%s'", expected, loginURL)
	}
}

func TestGetLoginURLWithRenew(t *testing.T) {
	client := NewClient("https://cas.example.com/cas", "http://localhost:8080")

	loginURL := client.GetLoginURLWithRenew()
	expected := "https://cas.example.com/cas/login?service=http%3A%2F%2Flocalhost%3A8080&renew=true"

	if loginURL != expected {
		t.Errorf("Expected login URL with renew to be '%s', got '%s'", expected, loginURL)
	}
}

func TestGetLoginURLWithGateway(t *testing.T) {
	client := NewClient("https://cas.example.com/cas", "http://localhost:8080")

	loginURL := client.GetLoginURLWithGateway()
	expected := "https://cas.example.com/cas/login?service=http%3A%2F%2Flocalhost%3A8080&gateway=true"

	if loginURL != expected {
		t.Errorf("Expected login URL with gateway to be '%s', got '%s'", expected, loginURL)
	}
}

func TestGetLogoutURL(t *testing.T) {
	client := NewClient("https://cas.example.com/cas", "http://localhost:8080")

	logoutURL := client.GetLogoutURL()
	expected := "https://cas.example.com/cas/logout"

	if logoutURL != expected {
		t.Errorf("Expected logout URL to be '%s', got '%s'", expected, logoutURL)
	}
}

func TestGetLogoutURLWithService(t *testing.T) {
	client := NewClient("https://cas.example.com/cas", "http://localhost:8080")

	logoutURL := client.GetLogoutURLWithService("http://localhost:8080/home")
	expected := "https://cas.example.com/cas/logout?service=http%3A%2F%2Flocalhost%3A8080%2Fhome"

	if logoutURL != expected {
		t.Errorf("Expected logout URL with service to be '%s', got '%s'", expected, logoutURL)
	}
}

func TestParseResponse_Success(t *testing.T) {
	client := NewClient("https://cas.example.com/cas", "http://localhost:8080")

	xmlResponse := `<cas:serviceResponse xmlns:cas="http://www.yale.edu/tp/cas">
		<cas:authenticationSuccess>
			<cas:user>testuser</cas:user>
			<cas:attributes>
				<cas:cn>Test User</cas:cn>
				<cas:mail>test@example.com</cas:mail>
			</cas:attributes>
		</cas:authenticationSuccess>
	</cas:serviceResponse>`

	user, err := client.parseResponse([]byte(xmlResponse))
	if err != nil {
		t.Fatalf("Expected no error, got %v", err)
	}

	if user.User != "testuser" {
		t.Errorf("Expected user to be 'testuser', got '%s'", user.User)
	}
}

func TestParseResponse_Failure(t *testing.T) {
	client := NewClient("https://cas.example.com/cas", "http://localhost:8080")

	xmlResponse := `<cas:serviceResponse xmlns:cas="http://www.yale.edu/tp/cas">
		<cas:authenticationFailure code="INVALID_TICKET">
			Ticket ST-123 not recognized
		</cas:authenticationFailure>
	</cas:serviceResponse>`

	_, err := client.parseResponse([]byte(xmlResponse))
	if err == nil {
		t.Fatal("Expected error for authentication failure")
	}
}

func TestGetTicketFromRequest(t *testing.T) {
	req := httptest.NewRequest("GET", "http://localhost:8080?ticket=ST-123456", nil)

	ticket := GetTicketFromRequest(req)
	if ticket != "ST-123456" {
		t.Errorf("Expected ticket to be 'ST-123456', got '%s'", ticket)
	}
}

func TestGetTicketFromRequest_NoTicket(t *testing.T) {
	req := httptest.NewRequest("GET", "http://localhost:8080", nil)

	ticket := GetTicketFromRequest(req)
	if ticket != "" {
		t.Errorf("Expected empty ticket, got '%s'", ticket)
	}
}

func TestValidateTicket_EmptyTicket(t *testing.T) {
	client := NewClient("https://cas.example.com/cas", "http://localhost:8080")

	_, err := client.ValidateTicket("")
	if err == nil {
		t.Fatal("Expected error for empty ticket")
	}
}

func TestValidateTicket_MockServer(t *testing.T) {
	// Create mock CAS server
	mockServer := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path == "/serviceValidate" {
			w.Header().Set("Content-Type", "application/xml")
			w.Write([]byte(`<cas:serviceResponse xmlns:cas="http://www.yale.edu/tp/cas">
				<cas:authenticationSuccess>
					<cas:user>testuser</cas:user>
				</cas:authenticationSuccess>
			</cas:serviceResponse>`))
		}
	}))
	defer mockServer.Close()

	client := NewClient(mockServer.URL, "http://localhost:8080")

	user, err := client.ValidateTicket("ST-123456")
	if err != nil {
		t.Fatalf("Expected no error, got %v", err)
	}

	if user.User != "testuser" {
		t.Errorf("Expected user to be 'testuser', got '%s'", user.User)
	}
}

func TestRemoveTicketFromURL(t *testing.T) {
	tests := []struct {
		input    string
		expected string
	}{
		{
			"http://localhost:8080?ticket=ST-123",
			"http://localhost:8080",
		},
		{
			"http://localhost:8080?foo=bar&ticket=ST-123",
			"http://localhost:8080?foo=bar",
		},
		{
			"http://localhost:8080?ticket=ST-123&foo=bar",
			"http://localhost:8080?foo=bar",
		},
		{
			"http://localhost:8080",
			"http://localhost:8080",
		},
		{
			"http://localhost:8080/path?ticket=ST-123&a=1&b=2",
			"http://localhost:8080/path?a=1&b=2",
		},
		{
			"http://localhost:8080/path?a=1&ticket=ST-123&b=2",
			"http://localhost:8080/path?a=1&b=2",
		},
	}

	for _, test := range tests {
		result := removeTicketFromURL(test.input)
		// URL query parameter order may vary, so we need to compare parsed URLs
		resultURL, _ := url.Parse(result)
		expectedURL, _ := url.Parse(test.expected)

		if resultURL.Scheme != expectedURL.Scheme ||
			resultURL.Host != expectedURL.Host ||
			resultURL.Path != expectedURL.Path {
			t.Errorf("removeTicketFromURL(%s) = %s, expected %s", test.input, result, test.expected)
			continue
		}

		// Compare query parameters
		resultQuery := resultURL.Query()
		expectedQuery := expectedURL.Query()
		if len(resultQuery) != len(expectedQuery) {
			t.Errorf("removeTicketFromURL(%s) query params count mismatch: got %d, expected %d",
				test.input, len(resultQuery), len(expectedQuery))
		}
	}
}

func TestMemorySessionStore(t *testing.T) {
	store := NewMemorySessionStore("test_session", 3600)

	// Test Set and Get
	w := httptest.NewRecorder()
	r := httptest.NewRequest("GET", "http://localhost:8080", nil)

	user := &User{
		User: "testuser",
		Attributes: map[string]interface{}{
			"email": "test@example.com",
		},
	}

	err := store.Set(w, r, user)
	if err != nil {
		t.Fatalf("Expected no error on Set, got %v", err)
	}

	// Get the cookie from response
	cookies := w.Result().Cookies()
	if len(cookies) == 0 {
		t.Fatal("Expected cookie to be set")
	}

	// Create new request with cookie
	r2 := httptest.NewRequest("GET", "http://localhost:8080", nil)
	r2.AddCookie(cookies[0])

	retrievedUser, err := store.Get(r2)
	if err != nil {
		t.Fatalf("Expected no error on Get, got %v", err)
	}

	if retrievedUser.User != user.User {
		t.Errorf("Expected user to be '%s', got '%s'", user.User, retrievedUser.User)
	}
}

func TestCookieSessionStore(t *testing.T) {
	store := NewCookieSessionStore("test_session", 3600, "test-secret-key-32-bytes-long!!")

	// Test Set and Get
	w := httptest.NewRecorder()
	r := httptest.NewRequest("GET", "http://localhost:8080", nil)

	user := &User{
		User: "testuser",
		Attributes: map[string]interface{}{
			"email": "test@example.com",
		},
	}

	err := store.Set(w, r, user)
	if err != nil {
		t.Fatalf("Expected no error on Set, got %v", err)
	}

	// Get the cookie from response
	cookies := w.Result().Cookies()
	if len(cookies) == 0 {
		t.Fatal("Expected cookie to be set")
	}

	// Create new request with cookie
	r2 := httptest.NewRequest("GET", "http://localhost:8080", nil)
	r2.AddCookie(cookies[0])

	retrievedUser, err := store.Get(r2)
	if err != nil {
		t.Fatalf("Expected no error on Get, got %v", err)
	}

	if retrievedUser.User != user.User {
		t.Errorf("Expected user to be '%s', got '%s'", user.User, retrievedUser.User)
	}
}

func TestCookieSessionStore_TamperedCookie(t *testing.T) {
	store := NewCookieSessionStore("test_session", 3600, "test-secret-key-32-bytes-long!!")

	// Create a tampered cookie
	r := httptest.NewRequest("GET", "http://localhost:8080", nil)
	r.AddCookie(&http.Cookie{
		Name:  "test_session",
		Value: "dGFtcGVyZWQ=.invalidsignature",
	})

	_, err := store.Get(r)
	if err == nil {
		t.Fatal("Expected error for tampered cookie")
	}
}

func TestGetLoginURLForService(t *testing.T) {
	client := NewClient("https://cas.example.com/cas", "http://localhost:8080")

	serviceURL := "http://localhost:8080/protected?foo=bar"
	loginURL := client.GetLoginURLForService(serviceURL)
	expected := "https://cas.example.com/cas/login?service=http%3A%2F%2Flocalhost%3A8080%2Fprotected%3Ffoo%3Dbar"

	if loginURL != expected {
		t.Errorf("Expected login URL to be '%s', got '%s'", expected, loginURL)
	}
}

func TestValidateTicketWithService(t *testing.T) {
	// Create mock CAS server
	mockServer := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path == "/serviceValidate" {
			// Verify the service parameter
			service := r.URL.Query().Get("service")
			if service != "http://localhost:8080/custom" {
				t.Errorf("Expected service to be 'http://localhost:8080/custom', got '%s'", service)
			}

			w.Header().Set("Content-Type", "application/xml")
			w.Write([]byte(`<cas:serviceResponse xmlns:cas="http://www.yale.edu/tp/cas">
				<cas:authenticationSuccess>
					<cas:user>testuser</cas:user>
				</cas:authenticationSuccess>
			</cas:serviceResponse>`))
		}
	}))
	defer mockServer.Close()

	client := NewClient(mockServer.URL, "http://localhost:8080")

	user, err := client.ValidateTicketWithService("ST-123456", "http://localhost:8080/custom")
	if err != nil {
		t.Fatalf("Expected no error, got %v", err)
	}

	if user.User != "testuser" {
		t.Errorf("Expected user to be 'testuser', got '%s'", user.User)
	}
}

func TestMiddleware_RedirectsToLogin(t *testing.T) {
	client := NewClient("https://cas.example.com/cas", "http://localhost:8080")
	store := NewMemorySessionStore("test_session", 3600)
	middleware := NewMiddleware(client, store)

	handler := middleware.Handler(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
	}))

	w := httptest.NewRecorder()
	r := httptest.NewRequest("GET", "http://localhost:8080/protected", nil)

	handler.ServeHTTP(w, r)

	if w.Code != http.StatusFound {
		t.Errorf("Expected status %d, got %d", http.StatusFound, w.Code)
	}

	location := w.Header().Get("Location")
	if location == "" {
		t.Fatal("Expected Location header to be set")
	}

	// Should redirect to CAS login with the current URL as service
	if !contains(location, "cas.example.com/cas/login") {
		t.Errorf("Expected redirect to CAS login, got %s", location)
	}
	if !contains(location, "service=") {
		t.Errorf("Expected service parameter in redirect URL, got %s", location)
	}
}

func TestMiddleware_IgnorePaths(t *testing.T) {
	client := NewClient("https://cas.example.com/cas", "http://localhost:8080")
	store := NewMemorySessionStore("test_session", 3600)
	middleware := NewMiddleware(client, store)
	middleware.IgnorePaths = []string{"/health", "/"}

	handler := middleware.Handler(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
		w.Write([]byte("OK"))
	}))

	// Test ignored path
	w := httptest.NewRecorder()
	r := httptest.NewRequest("GET", "http://localhost:8080/health", nil)

	handler.ServeHTTP(w, r)

	if w.Code != http.StatusOK {
		t.Errorf("Expected status %d for ignored path, got %d", http.StatusOK, w.Code)
	}
}

func contains(s, substr string) bool {
	return len(s) >= len(substr) && (s == substr || len(s) > 0 && containsAt(s, substr))
}

func containsAt(s, substr string) bool {
	for i := 0; i <= len(s)-len(substr); i++ {
		if s[i:i+len(substr)] == substr {
			return true
		}
	}
	return false
}
