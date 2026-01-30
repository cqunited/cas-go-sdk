// Package cas provides a CAS (Central Authentication Service) client SDK for Go.
// It supports CAS 2.0 protocol for authentication with CAS servers.
package cas

import (
	"encoding/xml"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"strings"
	"time"
)

// Version constants
const (
	CAS10 = "1.0"
	CAS20 = "2.0"
)

// Client represents a CAS client configuration
type Client struct {
	// CAS server URL prefix (e.g., https://cas.example.com/cas)
	CASServerURLPrefix string
	// Service URL (your application URL)
	ServiceURL string
	// HTTP client for making requests
	HTTPClient *http.Client
	// Skip SSL verification (not recommended for production)
	InsecureSkipVerify bool
}

// NewClient creates a new CAS client
func NewClient(casServerURL, serviceURL string) *Client {
	return &Client{
		CASServerURLPrefix: strings.TrimSuffix(casServerURL, "/"),
		ServiceURL:         serviceURL,
		HTTPClient: &http.Client{
			Timeout: 30 * time.Second,
		},
	}
}

// User represents an authenticated CAS user
type User struct {
	// Username from CAS
	User string
	// Additional attributes from CAS response
	Attributes map[string]interface{}
	// Proxy Granting Ticket (if proxy mode)
	ProxyGrantingTicket string
	// Proxies chain
	Proxies []string
}

// ServiceResponse represents the CAS server response
type ServiceResponse struct {
	XMLName               xml.Name               `xml:"serviceResponse"`
	AuthenticationSuccess *AuthenticationSuccess `xml:"authenticationSuccess"`
	AuthenticationFailure *AuthenticationFailure `xml:"authenticationFailure"`
}

// AuthenticationSuccess represents a successful authentication response
type AuthenticationSuccess struct {
	User                string    `xml:"user"`
	ProxyGrantingTicket string    `xml:"proxyGrantingTicket"`
	Proxies             *Proxies  `xml:"proxies"`
	Attributes          *CASAttrs `xml:"attributes"`
}

// Proxies represents the proxy chain
type Proxies struct {
	Proxy []string `xml:"proxy"`
}

// CASAttrs represents CAS attributes in the response
type CASAttrs struct {
	XMLName xml.Name
	Attrs   []CASAttr `xml:",any"`
}

// CASAttr represents a single CAS attribute
type CASAttr struct {
	XMLName xml.Name
	Value   string `xml:",chardata"`
}

// AuthenticationFailure represents a failed authentication response
type AuthenticationFailure struct {
	Code    string `xml:"code,attr"`
	Message string `xml:",chardata"`
}

// GetLoginURL returns the CAS login URL with service parameter
func (c *Client) GetLoginURL() string {
	return c.GetLoginURLForService(c.ServiceURL)
}

// GetLoginURLForService returns the CAS login URL with a specific service URL
func (c *Client) GetLoginURLForService(serviceURL string) string {
	return fmt.Sprintf("%s/login?service=%s", c.CASServerURLPrefix, url.QueryEscape(serviceURL))
}

// GetLoginURLWithRenew returns the CAS login URL with renew parameter
func (c *Client) GetLoginURLWithRenew() string {
	return fmt.Sprintf("%s/login?service=%s&renew=true", c.CASServerURLPrefix, url.QueryEscape(c.ServiceURL))
}

// GetLoginURLWithGateway returns the CAS login URL with gateway parameter
func (c *Client) GetLoginURLWithGateway() string {
	return fmt.Sprintf("%s/login?service=%s&gateway=true", c.CASServerURLPrefix, url.QueryEscape(c.ServiceURL))
}

// GetLogoutURL returns the CAS logout URL
func (c *Client) GetLogoutURL() string {
	return fmt.Sprintf("%s/logout", c.CASServerURLPrefix)
}

// GetLogoutURLWithService returns the CAS logout URL with service redirect
func (c *Client) GetLogoutURLWithService(redirectURL string) string {
	return fmt.Sprintf("%s/logout?service=%s", c.CASServerURLPrefix, url.QueryEscape(redirectURL))
}

// ValidateTicket validates a CAS ticket and returns user information
func (c *Client) ValidateTicket(ticket string) (*User, error) {
	return c.ValidateTicketWithService(ticket, c.ServiceURL)
}

// ValidateTicketWithService validates a CAS ticket with a specific service URL
func (c *Client) ValidateTicketWithService(ticket, serviceURL string) (*User, error) {
	if ticket == "" {
		return nil, errors.New("ticket cannot be empty")
	}

	validateURL := fmt.Sprintf("%s/serviceValidate?ticket=%s&service=%s",
		c.CASServerURLPrefix,
		url.QueryEscape(ticket),
		url.QueryEscape(serviceURL))

	resp, err := c.HTTPClient.Get(validateURL)
	if err != nil {
		return nil, fmt.Errorf("failed to validate ticket: %w", err)
	}
	defer resp.Body.Close()

	body, err := io.ReadAll(resp.Body)
	if err != nil {
		return nil, fmt.Errorf("failed to read response: %w", err)
	}

	return c.parseResponse(body)
}

// ValidateProxyTicket validates a proxy ticket
func (c *Client) ValidateProxyTicket(ticket string) (*User, error) {
	if ticket == "" {
		return nil, errors.New("ticket cannot be empty")
	}

	validateURL := fmt.Sprintf("%s/proxyValidate?ticket=%s&service=%s",
		c.CASServerURLPrefix,
		url.QueryEscape(ticket),
		url.QueryEscape(c.ServiceURL))

	resp, err := c.HTTPClient.Get(validateURL)
	if err != nil {
		return nil, fmt.Errorf("failed to validate proxy ticket: %w", err)
	}
	defer resp.Body.Close()

	body, err := io.ReadAll(resp.Body)
	if err != nil {
		return nil, fmt.Errorf("failed to read response: %w", err)
	}

	return c.parseResponse(body)
}

// parseResponse parses the CAS XML response
func (c *Client) parseResponse(body []byte) (*User, error) {
	var serviceResp ServiceResponse
	if err := xml.Unmarshal(body, &serviceResp); err != nil {
		return nil, fmt.Errorf("failed to parse CAS response: %w", err)
	}

	if serviceResp.AuthenticationFailure != nil {
		return nil, fmt.Errorf("authentication failed: %s (code: %s)",
			strings.TrimSpace(serviceResp.AuthenticationFailure.Message),
			serviceResp.AuthenticationFailure.Code)
	}

	if serviceResp.AuthenticationSuccess == nil {
		return nil, errors.New("invalid CAS response: no success or failure element")
	}

	success := serviceResp.AuthenticationSuccess
	user := &User{
		User:                success.User,
		Attributes:          make(map[string]interface{}),
		ProxyGrantingTicket: success.ProxyGrantingTicket,
	}

	// Parse attributes
	if success.Attributes != nil {
		for _, attr := range success.Attributes.Attrs {
			user.Attributes[attr.XMLName.Local] = attr.Value
		}
	}

	// Parse proxies
	if success.Proxies != nil {
		user.Proxies = success.Proxies.Proxy
	}

	return user, nil
}

// GetTicketFromRequest extracts the CAS ticket from an HTTP request
func GetTicketFromRequest(r *http.Request) string {
	return r.URL.Query().Get("ticket")
}

// RedirectToLogin redirects the user to CAS login page
func (c *Client) RedirectToLogin(w http.ResponseWriter, r *http.Request) {
	http.Redirect(w, r, c.GetLoginURL(), http.StatusFound)
}

// RedirectToLogout redirects the user to CAS logout page
func (c *Client) RedirectToLogout(w http.ResponseWriter, r *http.Request) {
	http.Redirect(w, r, c.GetLogoutURL(), http.StatusFound)
}
