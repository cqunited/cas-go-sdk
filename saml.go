package cas

import (
	"bytes"
	"encoding/xml"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"strings"
	"time"
)

// SAML constants
const (
	SAMLVersion11 = "S1"
)

// SAMLRequest represents a SAML validation request
type SAMLRequest struct {
	XMLName   xml.Name `xml:"SOAP-ENV:Envelope"`
	SoapEnvNS string   `xml:"xmlns:SOAP-ENV,attr"`
	Header    string   `xml:"SOAP-ENV:Header"`
	Body      SAMLBody `xml:"SOAP-ENV:Body"`
}

// SAMLBody represents the SOAP body
type SAMLBody struct {
	Request SAMLPRequest `xml:"samlp:Request"`
}

// SAMLPRequest represents the SAML protocol request
type SAMLPRequest struct {
	XMLNS        string `xml:"xmlns:samlp,attr"`
	MajorVersion string `xml:"MajorVersion,attr"`
	MinorVersion string `xml:"MinorVersion,attr"`
	RequestID    string `xml:"RequestID,attr"`
	IssueInstant string `xml:"IssueInstant,attr"`
	Artifact     string `xml:"samlp:AssertionArtifact"`
}

// SAMLResponse represents the SAML validation response
type SAMLResponse struct {
	XMLName xml.Name         `xml:"Envelope"`
	Body    SAMLResponseBody `xml:"Body"`
}

// SAMLResponseBody represents the SAML response body
type SAMLResponseBody struct {
	Response SAMLPResponse `xml:"Response"`
}

// SAMLPResponse represents the SAML protocol response
type SAMLPResponse struct {
	Status    SAMLStatus    `xml:"Status"`
	Assertion SAMLAssertion `xml:"Assertion"`
}

// SAMLStatus represents the SAML status
type SAMLStatus struct {
	StatusCode SAMLStatusCode `xml:"StatusCode"`
}

// SAMLStatusCode represents the SAML status code
type SAMLStatusCode struct {
	Value string `xml:"Value,attr"`
}

// SAMLAssertion represents the SAML assertion
type SAMLAssertion struct {
	AuthenticationStatement SAMLAuthStatement `xml:"AuthenticationStatement"`
	AttributeStatement      SAMLAttrStatement `xml:"AttributeStatement"`
}

// SAMLAuthStatement represents the authentication statement
type SAMLAuthStatement struct {
	Subject SAMLSubject `xml:"Subject"`
}

// SAMLSubject represents the SAML subject
type SAMLSubject struct {
	NameIdentifier string `xml:"NameIdentifier"`
}

// SAMLAttrStatement represents the attribute statement
type SAMLAttrStatement struct {
	Attributes []SAMLAttribute `xml:"Attribute"`
}

// SAMLAttribute represents a SAML attribute
type SAMLAttribute struct {
	Name   string   `xml:"AttributeName,attr"`
	Values []string `xml:"AttributeValue"`
}

// ValidateSAMLTicket validates a ticket using SAML 1.1 protocol
func (c *Client) ValidateSAMLTicket(ticket string) (*User, error) {
	if ticket == "" {
		return nil, fmt.Errorf("ticket cannot be empty")
	}

	validateURL := fmt.Sprintf("%s/samlValidate?TARGET=%s",
		c.CASServerURLPrefix,
		url.QueryEscape(c.ServiceURL))

	// Build SAML request
	samlReq := buildSAMLRequest(ticket)
	reqBody, err := xml.Marshal(samlReq)
	if err != nil {
		return nil, fmt.Errorf("failed to build SAML request: %w", err)
	}

	// Send POST request
	req, err := http.NewRequest("POST", validateURL, bytes.NewReader(reqBody))
	if err != nil {
		return nil, fmt.Errorf("failed to create request: %w", err)
	}
	req.Header.Set("Content-Type", "text/xml; charset=utf-8")
	req.Header.Set("SOAPAction", "http://www.oasis-open.org/committees/security")

	resp, err := c.HTTPClient.Do(req)
	if err != nil {
		return nil, fmt.Errorf("failed to validate SAML ticket: %w", err)
	}
	defer resp.Body.Close()

	body, err := io.ReadAll(resp.Body)
	if err != nil {
		return nil, fmt.Errorf("failed to read response: %w", err)
	}

	return parseSAMLResponse(body)
}

func buildSAMLRequest(ticket string) SAMLRequest {
	return SAMLRequest{
		SoapEnvNS: "http://schemas.xmlsoap.org/soap/envelope/",
		Header:    "",
		Body: SAMLBody{
			Request: SAMLPRequest{
				XMLNS:        "urn:oasis:names:tc:SAML:1.0:protocol",
				MajorVersion: "1",
				MinorVersion: "1",
				RequestID:    fmt.Sprintf("_%d", time.Now().UnixNano()),
				IssueInstant: time.Now().UTC().Format(time.RFC3339),
				Artifact:     ticket,
			},
		},
	}
}

func parseSAMLResponse(body []byte) (*User, error) {
	var samlResp SAMLResponse
	if err := xml.Unmarshal(body, &samlResp); err != nil {
		return nil, fmt.Errorf("failed to parse SAML response: %w", err)
	}

	// Check status
	statusCode := samlResp.Body.Response.Status.StatusCode.Value
	if !strings.Contains(statusCode, "Success") {
		return nil, fmt.Errorf("SAML authentication failed: %s", statusCode)
	}

	// Extract user info
	user := &User{
		User:       samlResp.Body.Response.Assertion.AuthenticationStatement.Subject.NameIdentifier,
		Attributes: make(map[string]interface{}),
	}

	// Extract attributes
	for _, attr := range samlResp.Body.Response.Assertion.AttributeStatement.Attributes {
		if len(attr.Values) == 1 {
			user.Attributes[attr.Name] = attr.Values[0]
		} else if len(attr.Values) > 1 {
			user.Attributes[attr.Name] = attr.Values
		}
	}

	return user, nil
}
