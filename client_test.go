package httpclient

import (
	"bytes"
	"context"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"
)

const (
	testSharedSecret = "testSharedSecret"
)

// TestNewAuthClient_NoneMode tests client creation with no authentication
func TestNewAuthClient_NoneMode(t *testing.T) {
	client, err := NewAuthClient(AuthModeNone, "")
	if err != nil {
		t.Fatalf("Failed to create client: %v", err)
	}

	if client == nil {
		t.Fatal("Expected non-nil client")
	}

	// Test that the client works
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		// Verify no auth headers were added
		if r.Header.Get("X-API-Secret") != "" || r.Header.Get("X-Signature") != "" {
			t.Error("No auth headers should be added in none mode")
		}
		w.WriteHeader(http.StatusOK)
	}))
	defer server.Close()

	req, _ := http.NewRequestWithContext(context.Background(), http.MethodGet, server.URL, nil)
	resp, err := client.Do(req)
	if err != nil {
		t.Fatalf("Request failed: %v", err)
	}
	defer func() { _ = resp.Body.Close() }()

	if resp.StatusCode != http.StatusOK {
		t.Errorf("Expected status 200, got %d", resp.StatusCode)
	}
}

// TestNewAuthClient_SimpleMode tests client with simple authentication
func TestNewAuthClient_SimpleMode(t *testing.T) {
	secret := "test-secret-key"
	client, err := NewAuthClient(AuthModeSimple, secret)
	if err != nil {
		t.Fatalf("Failed to create client: %v", err)
	}

	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		// Verify auth header
		if r.Header.Get("X-API-Secret") != secret {
			t.Errorf("Expected X-API-Secret=%s, got %s", secret, r.Header.Get("X-API-Secret"))
		}
		w.WriteHeader(http.StatusOK)
	}))
	defer server.Close()

	req, _ := http.NewRequestWithContext(context.Background(), http.MethodGet, server.URL, nil)
	resp, err := client.Do(req)
	if err != nil {
		t.Fatalf("Request failed: %v", err)
	}
	defer func() { _ = resp.Body.Close() }()

	if resp.StatusCode != http.StatusOK {
		t.Errorf("Expected status 200, got %d", resp.StatusCode)
	}
}

// TestNewAuthClient_HMACMode tests client with HMAC authentication
func TestNewAuthClient_HMACMode(t *testing.T) {
	secret := "testSharedSecret"
	client, err := NewAuthClient(AuthModeHMAC, secret)
	if err != nil {
		t.Fatalf("Failed to create client: %v", err)
	}

	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		// Verify HMAC headers exist
		if r.Header.Get("X-Signature") == "" {
			t.Error("Expected X-Signature header")
		}
		if r.Header.Get("X-Timestamp") == "" {
			t.Error("Expected X-Timestamp header")
		}
		if r.Header.Get("X-Nonce") == "" {
			t.Error("Expected X-Nonce header")
		}
		w.WriteHeader(http.StatusOK)
	}))
	defer server.Close()

	req, _ := http.NewRequestWithContext(
		context.Background(),
		http.MethodPost,
		server.URL,
		bytes.NewReader([]byte(`{"test":"data"}`)),
	)
	req.Header.Set("Content-Type", "application/json")
	resp, err := client.Do(req)
	if err != nil {
		t.Fatalf("Request failed: %v", err)
	}
	defer func() { _ = resp.Body.Close() }()

	if resp.StatusCode != http.StatusOK {
		t.Errorf("Expected status 200, got %d", resp.StatusCode)
	}
}

// TestAuthRoundTripper_NilBody tests handling of requests with no body
func TestAuthRoundTripper_NilBody(t *testing.T) {
	client, err := NewAuthClient(AuthModeHMAC, "secret")
	if err != nil {
		t.Fatalf("Failed to create client: %v", err)
	}

	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		// Signature should still be added even with nil body
		if r.Header.Get("X-Signature") == "" {
			t.Error("Expected X-Signature header even with nil body")
		}
		w.WriteHeader(http.StatusOK)
	}))
	defer server.Close()

	// GET request with nil body
	req, _ := http.NewRequestWithContext(context.Background(), http.MethodGet, server.URL, nil)
	resp, err := client.Do(req)
	if err != nil {
		t.Fatalf("Request failed: %v", err)
	}
	defer func() { _ = resp.Body.Close() }()

	if resp.StatusCode != http.StatusOK {
		t.Errorf("Expected status 200, got %d", resp.StatusCode)
	}
}

// TestAuthRoundTripper_BodyPreservation tests that body is preserved after signing
func TestAuthRoundTripper_BodyPreservation(t *testing.T) {
	originalBody := []byte(`{"test":"data","number":123}`)

	serverConfig := NewAuthConfig(AuthModeHMAC, testSharedSecret)
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		// Verify signature
		if err := serverConfig.Verify(r); err != nil {
			t.Errorf("Signature verification failed: %v", err)
			http.Error(w, "Auth failed", http.StatusUnauthorized)
			return
		}

		// Read body after verification
		bodyAfterVerify, err := io.ReadAll(r.Body)
		if err != nil {
			t.Errorf("Failed to read body: %v", err)
		}

		// Verify body is intact
		if !bytes.Equal(bodyAfterVerify, originalBody) {
			t.Errorf("Body mismatch.\nExpected: %s\nGot: %s", originalBody, bodyAfterVerify)
		}

		w.WriteHeader(http.StatusOK)
		_, _ = w.Write(bodyAfterVerify)
	}))
	defer server.Close()

	client, err := NewAuthClient(AuthModeHMAC, testSharedSecret)
	if err != nil {
		t.Fatalf("Failed to create client: %v", err)
	}
	// Use a path to ensure proper URL handling
	req, _ := http.NewRequestWithContext(
		context.Background(),
		http.MethodPost,
		server.URL+"/api/test",
		bytes.NewReader(originalBody),
	)
	req.Header.Set("Content-Type", "application/json")
	resp, err := client.Do(req)
	if err != nil {
		t.Fatalf("Request failed: %v", err)
	}
	defer func() { _ = resp.Body.Close() }()

	if resp.StatusCode != http.StatusOK {
		body, _ := io.ReadAll(resp.Body)
		t.Fatalf("Expected status 200, got %d. Response: %s", resp.StatusCode, body)
	}

	// Verify response body matches
	respBody, _ := io.ReadAll(resp.Body)
	if !bytes.Equal(respBody, originalBody) {
		t.Errorf("Response body mismatch.\nExpected: %s\nGot: %s", originalBody, respBody)
	}
}

// TestNewAuthClient_WithTimeout tests custom timeout option
func TestNewAuthClient_WithTimeout(t *testing.T) {
	// Create server with slow response
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		time.Sleep(200 * time.Millisecond)
		w.WriteHeader(http.StatusOK)
	}))
	defer server.Close()

	// Client with 100ms timeout (should timeout)
	client1, err := NewAuthClient(AuthModeNone, "", WithTimeout(100*time.Millisecond))
	if err != nil {
		t.Fatalf("Failed to create client: %v", err)
	}
	req1, _ := http.NewRequestWithContext(context.Background(), http.MethodGet, server.URL, nil)
	resp, err := client1.Do(req1)
	if err == nil {
		t.Error("Expected timeout error")
	}
	if resp != nil {
		_ = resp.Body.Close()
	}

	// Client with 300ms timeout (should succeed)
	client2, err := NewAuthClient(AuthModeNone, "", WithTimeout(300*time.Millisecond))
	if err != nil {
		t.Fatalf("Failed to create client: %v", err)
	}
	req2, _ := http.NewRequestWithContext(context.Background(), http.MethodGet, server.URL, nil)
	resp2, err2 := client2.Do(req2)
	if err2 != nil {
		t.Errorf("Request should succeed: %v", err2)
	}
	if resp2 != nil {
		_ = resp2.Body.Close()
	}
}

// TestNewAuthClient_WithMaxBodySize tests body size limit option
func TestNewAuthClient_WithMaxBodySize(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
	}))
	defer server.Close()

	// Client with 100-byte limit
	client, err := NewAuthClient(AuthModeHMAC, "secret", WithMaxBodySize(100))
	if err != nil {
		t.Fatalf("Failed to create client: %v", err)
	}

	// Small body (should succeed)
	smallBody := bytes.Repeat([]byte("x"), 50)
	req, _ := http.NewRequestWithContext(
		context.Background(),
		http.MethodPost,
		server.URL,
		bytes.NewReader(smallBody),
	)
	req.Header.Set("Content-Type", "text/plain")
	resp, err := client.Do(req)
	if err != nil {
		t.Errorf("Small body should succeed: %v", err)
	}
	if resp != nil {
		_ = resp.Body.Close()
	}

	// Large body (should fail)
	largeBody := bytes.Repeat([]byte("x"), 200)
	req2, _ := http.NewRequestWithContext(
		context.Background(),
		http.MethodPost,
		server.URL,
		bytes.NewReader(largeBody),
	)
	req2.Header.Set("Content-Type", "text/plain")
	resp2, err := client.Do(req2)
	if err == nil {
		t.Error("Expected error for large body")
	}
	if resp2 != nil {
		_ = resp2.Body.Close()
	}
	if !strings.Contains(err.Error(), "exceeds maximum size") {
		t.Errorf("Wrong error message: %v", err)
	}
}

// TestNewAuthClient_WithSkipAuthFunc tests conditional authentication skipping
func TestNewAuthClient_WithSkipAuthFunc(t *testing.T) {
	callCount := 0
	authHeaderCount := 0

	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		callCount++
		if r.Header.Get("X-Signature") != "" {
			authHeaderCount++
		}
		w.WriteHeader(http.StatusOK)
	}))
	defer server.Close()

	client, err := NewAuthClient(
		AuthModeHMAC,
		"secret",
		WithSkipAuthFunc(func(req *http.Request) bool {
			// Skip auth for /health endpoints
			return strings.HasPrefix(req.URL.Path, "/health")
		}),
	)
	if err != nil {
		t.Fatalf("Failed to create client: %v", err)
	}

	// Health check request (should skip auth)
	req1, _ := http.NewRequestWithContext(
		context.Background(),
		http.MethodGet,
		server.URL+"/health",
		nil,
	)
	resp1, err := client.Do(req1)
	if err != nil {
		t.Errorf("Health check failed: %v", err)
	}
	if resp1 != nil {
		_ = resp1.Body.Close()
	}

	// Normal request (should add auth)
	req2, _ := http.NewRequestWithContext(
		context.Background(),
		http.MethodGet,
		server.URL+"/api/data",
		nil,
	)
	resp2, err := client.Do(req2)
	if err != nil {
		t.Errorf("API request failed: %v", err)
	}
	if resp2 != nil {
		_ = resp2.Body.Close()
	}

	// Verify: 2 requests made, but only 1 with auth headers
	if callCount != 2 {
		t.Errorf("Expected 2 requests, got %d", callCount)
	}
	if authHeaderCount != 1 {
		t.Errorf("Expected 1 request with auth headers, got %d", authHeaderCount)
	}
}

// TestNewAuthClient_WithCustomHeaders tests custom header names
func TestNewAuthClient_WithCustomHeaders(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		// Check for custom headers
		if r.Header.Get("X-Sig") == "" {
			t.Error("Expected custom X-Sig header")
		}
		if r.Header.Get("X-Time") == "" {
			t.Error("Expected custom X-Time header")
		}
		if r.Header.Get("X-ID") == "" {
			t.Error("Expected custom X-ID header")
		}

		// Verify default headers are NOT present
		if r.Header.Get("X-Signature") != "" {
			t.Error("Default X-Signature header should not be present")
		}

		w.WriteHeader(http.StatusOK)
	}))
	defer server.Close()

	client, err := NewAuthClient(
		AuthModeHMAC,
		"secret",
		WithHMACHeaders("X-Sig", "X-Time", "X-ID"),
	)
	if err != nil {
		t.Fatalf("Failed to create client: %v", err)
	}

	req, _ := http.NewRequestWithContext(
		context.Background(),
		http.MethodPost,
		server.URL,
		bytes.NewReader([]byte(`{"test":"data"}`)),
	)
	req.Header.Set("Content-Type", "application/json")
	resp, err := client.Do(req)
	if err != nil {
		t.Fatalf("Request failed: %v", err)
	}
	defer func() { _ = resp.Body.Close() }()

	if resp.StatusCode != http.StatusOK {
		t.Errorf("Expected status 200, got %d", resp.StatusCode)
	}
}

// TestNewAuthClient_WithHeaderName tests custom header name for simple mode
func TestNewAuthClient_WithHeaderName(t *testing.T) {
	secret := "my-api-key"

	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		// Check for custom header
		if r.Header.Get("Authorization") != secret {
			t.Errorf("Expected Authorization=%s, got %s", secret, r.Header.Get("Authorization"))
		}

		// Verify default header is NOT present
		if r.Header.Get("X-API-Secret") != "" {
			t.Error("Default X-API-Secret header should not be present")
		}

		w.WriteHeader(http.StatusOK)
	}))
	defer server.Close()

	client, err := NewAuthClient(
		AuthModeSimple,
		secret,
		WithHeaderName("Authorization"),
	)
	if err != nil {
		t.Fatalf("Failed to create client: %v", err)
	}

	req, _ := http.NewRequestWithContext(context.Background(), http.MethodGet, server.URL, nil)
	resp, err := client.Do(req)
	if err != nil {
		t.Fatalf("Request failed: %v", err)
	}
	defer func() { _ = resp.Body.Close() }()

	if resp.StatusCode != http.StatusOK {
		t.Errorf("Expected status 200, got %d", resp.StatusCode)
	}
}

// TestNewAuthClient_WithCustomTransport tests custom transport option
func TestNewAuthClient_WithCustomTransport(t *testing.T) {
	transportUsed := false

	customTransport := &customRoundTripper{
		base: http.DefaultTransport,
		onRoundTrip: func(req *http.Request) {
			transportUsed = true
		},
	}

	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
	}))
	defer server.Close()

	client, err := NewAuthClient(
		AuthModeNone,
		"",
		WithTransport(customTransport),
	)
	if err != nil {
		t.Fatalf("Failed to create client: %v", err)
	}

	req, _ := http.NewRequestWithContext(context.Background(), http.MethodGet, server.URL, nil)
	resp, err := client.Do(req)
	if err != nil {
		t.Fatalf("Request failed: %v", err)
	}
	defer func() { _ = resp.Body.Close() }()

	if !transportUsed {
		t.Error("Custom transport was not used")
	}
}

// TestNewAuthClient_MultipleOptions tests combining multiple options
func TestNewAuthClient_MultipleOptions(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		// For /health, verify no auth headers
		if strings.HasPrefix(r.URL.Path, "/health") {
			if r.Header.Get("X-Sig") != "" {
				t.Error("Health check should not have auth headers")
			}
		} else {
			// For other paths, verify custom headers exist
			if r.Header.Get("X-Sig") == "" {
				t.Error("Expected custom X-Sig header for non-health endpoint")
			}
		}

		w.WriteHeader(http.StatusOK)
	}))
	defer server.Close()

	client, err := NewAuthClient(
		AuthModeHMAC,
		"secret",
		WithTimeout(10*time.Second),
		WithMaxBodySize(1024*1024),
		WithHMACHeaders("X-Sig", "X-Time", "X-ID"),
		WithSkipAuthFunc(func(req *http.Request) bool {
			return strings.HasPrefix(req.URL.Path, "/health")
		}),
	)
	if err != nil {
		t.Fatalf("Failed to create client: %v", err)
	}

	// Test normal request
	req1, _ := http.NewRequestWithContext(
		context.Background(),
		http.MethodPost,
		server.URL+"/api",
		bytes.NewReader([]byte(`{"test":"data"}`)),
	)
	req1.Header.Set("Content-Type", "application/json")
	resp1, err := client.Do(req1)
	if err != nil {
		t.Errorf("Normal request failed: %v", err)
	}
	if resp1 != nil {
		_ = resp1.Body.Close()
	}

	// Test health check
	req2, _ := http.NewRequestWithContext(
		context.Background(),
		http.MethodGet,
		server.URL+"/health",
		nil,
	)
	resp2, err := client.Do(req2)
	if err != nil {
		t.Errorf("Health check failed: %v", err)
	}
	if resp2 != nil {
		_ = resp2.Body.Close()
	}
}

// TestAuthRoundTripper_Integration_HMAC is a comprehensive integration test
func TestAuthRoundTripper_Integration_HMAC(t *testing.T) {
	secret := "testSharedSecret"

	// Create test server that verifies signatures
	serverConfig := NewAuthConfig(AuthModeHMAC, secret)
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		// Verify signature
		if err := serverConfig.Verify(r); err != nil {
			t.Errorf("Signature verification failed: %v", err)
			http.Error(w, "Auth failed: "+err.Error(), http.StatusUnauthorized)
			return
		}

		// Read and echo body
		body, err := io.ReadAll(r.Body)
		if err != nil {
			t.Errorf("Failed to read body: %v", err)
			http.Error(w, "Failed to read body", http.StatusBadRequest)
			return
		}

		w.WriteHeader(http.StatusOK)
		_, _ = w.Write([]byte("Body: "))
		_, _ = w.Write(body)
	}))
	defer server.Close()

	// Create client
	client, err := NewAuthClient(AuthModeHMAC, testSharedSecret)
	if err != nil {
		t.Fatalf("Failed to create client: %v", err)
	}

	// Test with query parameters (should be included in signature)
	reqBody := []byte(`{"test": "data"}`)
	req, _ := http.NewRequestWithContext(
		context.Background(),
		http.MethodPost,
		server.URL+"/api/test?param=value&foo=bar",
		bytes.NewReader(reqBody),
	)
	req.Header.Set("Content-Type", "application/json")
	resp, err := client.Do(req)
	if err != nil {
		t.Fatalf("Request failed: %v", err)
	}
	defer func() { _ = resp.Body.Close() }()

	if resp.StatusCode != http.StatusOK {
		body, _ := io.ReadAll(resp.Body)
		t.Fatalf("Expected status 200, got %d. Body: %s", resp.StatusCode, body)
	}

	// Verify response
	respBody, _ := io.ReadAll(resp.Body)
	expectedResp := "Body: " + string(reqBody)
	if string(respBody) != expectedResp {
		t.Errorf("Response mismatch.\nExpected: %s\nGot: %s", expectedResp, respBody)
	}
}

// TestAuthRoundTripper_ErrorHandling tests various error scenarios
func TestAuthRoundTripper_ErrorHandling(t *testing.T) {
	// Test with missing secret
	client, err := NewAuthClient(AuthModeSimple, "")
	if err != nil {
		t.Fatalf("Failed to create client: %v", err)
	}

	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
	}))
	defer server.Close()

	req, _ := http.NewRequestWithContext(context.Background(), http.MethodGet, server.URL, nil)
	resp, err := client.Do(req)
	if err == nil {
		t.Error("Expected error for missing secret in simple mode")
	}
	if resp != nil {
		_ = resp.Body.Close()
	}
	if !strings.Contains(err.Error(), "secret is required") {
		t.Errorf("Wrong error message: %v", err)
	}
}

// TestNewAuthClient_WithContext tests that request context is preserved
func TestNewAuthClient_WithContext(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
	}))
	defer server.Close()

	client, err := NewAuthClient(AuthModeHMAC, "secret")
	if err != nil {
		t.Fatalf("Failed to create client: %v", err)
	}

	// Create request with context
	ctx, cancel := context.WithCancel(context.Background())
	req, _ := http.NewRequestWithContext(ctx, http.MethodGet, server.URL, nil)

	// Cancel context before sending
	cancel()

	resp, err := client.Do(req)
	if err == nil {
		t.Error("Expected context cancellation error")
	}
	if resp != nil {
		_ = resp.Body.Close()
	}
}

// customRoundTripper is a helper for testing custom transports
type customRoundTripper struct {
	base        http.RoundTripper
	onRoundTrip func(*http.Request)
}

func (t *customRoundTripper) RoundTrip(req *http.Request) (*http.Response, error) {
	if t.onRoundTrip != nil {
		t.onRoundTrip(req)
	}
	return t.base.RoundTrip(req)
}

// TestWithRequestID tests request ID generation and injection
func TestWithRequestID(t *testing.T) {
	requestIDCounter := 0
	requestIDFunc := func() string {
		requestIDCounter++
		return "test-request-" + string(rune('0'+requestIDCounter))
	}

	// Create test server that verifies request ID header
	var receivedRequestID string
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		receivedRequestID = r.Header.Get(DefaultRequestIDHeader)
		w.WriteHeader(http.StatusOK)
	}))
	defer server.Close()

	// Create client with request ID function
	client, err := NewAuthClient(
		AuthModeNone,
		"",
		WithRequestID(requestIDFunc),
	)
	if err != nil {
		t.Fatalf("Failed to create client: %v", err)
	}

	// Make request
	req, _ := http.NewRequestWithContext(context.Background(), http.MethodGet, server.URL, nil)
	resp, err := client.Do(req)
	if err != nil {
		t.Fatalf("Request failed: %v", err)
	}
	defer func() { _ = resp.Body.Close() }()

	// Verify request ID was added
	if receivedRequestID != "test-request-1" {
		t.Errorf("Expected request ID 'test-request-1', got '%s'", receivedRequestID)
	}
}

// TestWithRequestID_CustomHeader tests custom request ID header name
func TestWithRequestID_CustomHeader(t *testing.T) {
	customHeader := "X-Correlation-ID"
	testRequestID := "custom-correlation-123"

	// Create test server
	var receivedRequestID string
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		receivedRequestID = r.Header.Get(customHeader)
		// Verify default header is not present
		if r.Header.Get(DefaultRequestIDHeader) != "" {
			t.Error("Default request ID header should not be present")
		}
		w.WriteHeader(http.StatusOK)
	}))
	defer server.Close()

	// Create client with custom request ID header
	client, err := NewAuthClient(
		AuthModeNone,
		"",
		WithRequestID(func() string { return testRequestID }),
		WithRequestIDHeader(customHeader),
	)
	if err != nil {
		t.Fatalf("Failed to create client: %v", err)
	}

	// Make request
	req, _ := http.NewRequestWithContext(context.Background(), http.MethodGet, server.URL, nil)
	resp, err := client.Do(req)
	if err != nil {
		t.Fatalf("Request failed: %v", err)
	}
	defer func() { _ = resp.Body.Close() }()

	// Verify custom request ID header was used
	if receivedRequestID != testRequestID {
		t.Errorf("Expected request ID '%s', got '%s'", testRequestID, receivedRequestID)
	}
}

// TestWithRequestID_PreservesUserProvidedID tests that user-provided request IDs are preserved
func TestWithRequestID_PreservesUserProvidedID(t *testing.T) {
	userProvidedID := "user-provided-id-999"

	// Create test server
	var receivedRequestID string
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		receivedRequestID = r.Header.Get(DefaultRequestIDHeader)
		w.WriteHeader(http.StatusOK)
	}))
	defer server.Close()

	// Create client with request ID function
	client, err := NewAuthClient(
		AuthModeNone,
		"",
		WithRequestID(func() string { return "auto-generated-id" }),
	)
	if err != nil {
		t.Fatalf("Failed to create client: %v", err)
	}

	// Make request with user-provided request ID
	req, _ := http.NewRequestWithContext(context.Background(), http.MethodGet, server.URL, nil)
	req.Header.Set(DefaultRequestIDHeader, userProvidedID)
	resp, err := client.Do(req)
	if err != nil {
		t.Fatalf("Request failed: %v", err)
	}
	defer func() { _ = resp.Body.Close() }()

	// Verify user-provided ID was preserved
	if receivedRequestID != userProvidedID {
		t.Errorf(
			"Expected user-provided request ID '%s', got '%s'",
			userProvidedID,
			receivedRequestID,
		)
	}
}

// TestWithRequestID_WithAuthentication tests request ID with HMAC authentication
func TestWithRequestID_WithAuthentication(t *testing.T) {
	testRequestID := "auth-request-123"
	secret := "test-secret"

	// Create test server that verifies both request ID and authentication
	var receivedRequestID string
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		receivedRequestID = r.Header.Get(DefaultRequestIDHeader)

		// Verify authentication headers are present
		if r.Header.Get(DefaultSignatureHeader) == "" {
			t.Error("Signature header missing")
		}
		if r.Header.Get(DefaultTimestampHeader) == "" {
			t.Error("Timestamp header missing")
		}
		if r.Header.Get(DefaultNonceHeader) == "" {
			t.Error("Nonce header missing")
		}

		w.WriteHeader(http.StatusOK)
	}))
	defer server.Close()

	// Create client with HMAC authentication and request ID
	client, err := NewAuthClient(
		AuthModeHMAC,
		secret,
		WithRequestID(func() string { return testRequestID }),
	)
	if err != nil {
		t.Fatalf("Failed to create client: %v", err)
	}

	// Make request
	req, _ := http.NewRequestWithContext(context.Background(), http.MethodGet, server.URL, nil)
	resp, err := client.Do(req)
	if err != nil {
		t.Fatalf("Request failed: %v", err)
	}
	defer func() { _ = resp.Body.Close() }()

	// Verify request ID was added
	if receivedRequestID != testRequestID {
		t.Errorf("Expected request ID '%s', got '%s'", testRequestID, receivedRequestID)
	}
}

// TestWithRequestID_WithSkipAuth tests request ID is added even when auth is skipped
func TestWithRequestID_WithSkipAuth(t *testing.T) {
	testRequestID := "skip-auth-request-456"

	// Create test server
	var receivedRequestID string
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		receivedRequestID = r.Header.Get(DefaultRequestIDHeader)

		// Verify auth headers are not present
		if r.Header.Get(DefaultSignatureHeader) != "" {
			t.Error("Signature header should not be present when auth is skipped")
		}

		w.WriteHeader(http.StatusOK)
	}))
	defer server.Close()

	// Create client with skip auth function and request ID
	client, err := NewAuthClient(
		AuthModeHMAC,
		"secret",
		WithRequestID(func() string { return testRequestID }),
		WithSkipAuthFunc(func(req *http.Request) bool {
			return true // Skip all requests
		}),
	)
	if err != nil {
		t.Fatalf("Failed to create client: %v", err)
	}

	// Make request
	req, _ := http.NewRequestWithContext(context.Background(), http.MethodGet, server.URL, nil)
	resp, err := client.Do(req)
	if err != nil {
		t.Fatalf("Request failed: %v", err)
	}
	defer func() { _ = resp.Body.Close() }()

	// Verify request ID was added even when auth was skipped
	if receivedRequestID != testRequestID {
		t.Errorf("Expected request ID '%s', got '%s'", testRequestID, receivedRequestID)
	}
}

// TestWithRequestID_NoFunction tests that no request ID header is added when function is not configured
func TestWithRequestID_NoFunction(t *testing.T) {
	// Create test server
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Header.Get(DefaultRequestIDHeader) != "" {
			t.Error("Request ID header should not be present when function is not configured")
		}
		w.WriteHeader(http.StatusOK)
	}))
	defer server.Close()

	// Create client without request ID function
	client, err := NewAuthClient(AuthModeNone, "")
	if err != nil {
		t.Fatalf("Failed to create client: %v", err)
	}

	// Make request
	req, _ := http.NewRequestWithContext(context.Background(), http.MethodGet, server.URL, nil)
	resp, err := client.Do(req)
	if err != nil {
		t.Fatalf("Request failed: %v", err)
	}
	defer func() { _ = resp.Body.Close() }()
}
