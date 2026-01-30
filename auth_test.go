package httpclient

import (
	"bytes"
	"context"
	"crypto/hmac"
	"crypto/sha256"
	"encoding/hex"
	"io"
	"net"
	"net/http"
	"strconv"
	"strings"
	"testing"
	"time"
)

const (
	testAPISecret      = "test-secret"
	testXSignature     = "X-Signature"
	testXTimestamp     = "X-Timestamp"
	testXNonce         = "X-Nonce"
	testXAPISecret     = "X-API-Secret"
	testExampleURL     = "http://example.com/api"
	testExampleAuthURL = "http://example.com/api/auth"
)

func TestAuthConfig_addAuthHeaders_None(t *testing.T) {
	config := &AuthConfig{
		Mode:   AuthModeNone,
		Secret: NewSecureString(testAPISecret),
	}

	req, err := http.NewRequestWithContext(
		context.Background(),
		"POST",
		testExampleURL,
		bytes.NewBufferString("test body"),
	)
	if err != nil {
		t.Fatalf("Failed to create request: %v", err)
	}

	err = config.addAuthHeaders(req, []byte("test body"))
	if err != nil {
		t.Errorf("addAuthHeaders() error = %v, want nil", err)
	}

	// Should not add any auth headers in none mode
	if req.Header.Get(testXAPISecret) != "" {
		t.Errorf("Expected no X-API-Secret header in none mode")
	}
	if req.Header.Get(testXSignature) != "" {
		t.Errorf("Expected no X-Signature header in none mode")
	}
}

func TestAuthConfig_addAuthHeaders_Simple(t *testing.T) {
	tests := []struct {
		name       string
		config     *AuthConfig
		wantHeader string
		wantValue  string
		wantErr    bool
	}{
		{
			name: "Simple mode with default header",
			config: &AuthConfig{
				Mode:   AuthModeSimple,
				Secret: NewSecureString("test-secret-123"),
			},
			wantHeader: "X-API-Secret",
			wantValue:  "test-secret-123",
			wantErr:    false,
		},
		{
			name: "Simple mode with custom header",
			config: &AuthConfig{
				Mode:       AuthModeSimple,
				Secret:     NewSecureString("my-custom-secret"),
				HeaderName: "X-Custom-Auth",
			},
			wantHeader: "X-Custom-Auth",
			wantValue:  "my-custom-secret",
			wantErr:    false,
		},
		{
			name: "Simple mode without secret",
			config: &AuthConfig{
				Mode:   AuthModeSimple,
				Secret: NewSecureString(""),
			},
			wantErr: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			req, err := http.NewRequestWithContext(
				context.Background(),
				"POST",
				testExampleURL,
				bytes.NewBufferString("test body"),
			)
			if err != nil {
				t.Fatalf("Failed to create request: %v", err)
			}

			err = tt.config.addAuthHeaders(req, []byte("test body"))
			if (err != nil) != tt.wantErr {
				t.Errorf("addAuthHeaders() error = %v, wantErr %v", err, tt.wantErr)
				return
			}

			if !tt.wantErr {
				got := req.Header.Get(tt.wantHeader)
				if got != tt.wantValue {
					t.Errorf("Header %s = %v, want %v", tt.wantHeader, got, tt.wantValue)
				}
			}
		})
	}
}

func TestAuthConfig_addAuthHeaders_HMAC(t *testing.T) {
	config := &AuthConfig{
		Mode:   AuthModeHMAC,
		Secret: NewSecureString("test-secret-hmac"),
	}

	body := []byte(`{"username":"test","password":"pass123"}`)
	req, err := http.NewRequestWithContext(
		context.Background(),
		"POST",
		testExampleAuthURL,
		bytes.NewBuffer(body),
	)
	if err != nil {
		t.Fatalf("Failed to create request: %v", err)
	}

	err = config.addAuthHeaders(req, body)
	if err != nil {
		t.Fatalf("addAuthHeaders() error = %v", err)
	}

	// Check that all required headers are present
	signature := req.Header.Get(testXSignature)
	if signature == "" {
		t.Errorf("Expected X-Signature header to be set")
	}

	timestamp := req.Header.Get(testXTimestamp)
	if timestamp == "" {
		t.Errorf("Expected X-Timestamp header to be set")
	}

	nonce := req.Header.Get(testXNonce)
	if nonce == "" {
		t.Errorf("Expected X-Nonce header to be set")
	}

	// Verify signature format (should be hex string)
	if len(signature) != 64 { // SHA256 hex string is 64 characters
		t.Errorf("Signature length = %d, want 64", len(signature))
	}

	// Verify timestamp is recent (within 1 second)
	ts, err := strconv.ParseInt(timestamp, 10, 64)
	if err != nil {
		t.Errorf("Failed to parse timestamp: %v", err)
	}

	timeDiff := time.Now().Unix() - ts
	if timeDiff > 1 {
		t.Errorf("Timestamp is too old: %d seconds", timeDiff)
	}
}

func TestAuthConfig_addAuthHeaders_HMAC_CustomHeaders(t *testing.T) {
	config := &AuthConfig{
		Mode:            AuthModeHMAC,
		Secret:          NewSecureString("test-secret"),
		SignatureHeader: "X-Custom-Sig",
		TimestampHeader: "X-Custom-Time",
		NonceHeader:     "X-Custom-Nonce",
	}

	body := []byte("test body")
	req, err := http.NewRequestWithContext(
		context.Background(),
		"POST",
		testExampleURL,
		bytes.NewBuffer(body),
	)
	if err != nil {
		t.Fatalf("Failed to create request: %v", err)
	}

	err = config.addAuthHeaders(req, body)
	if err != nil {
		t.Fatalf("addAuthHeaders() error = %v", err)
	}

	// Check custom headers
	if req.Header.Get("X-Custom-Sig") == "" {
		t.Errorf("Expected X-Custom-Sig header to be set")
	}
	if req.Header.Get("X-Custom-Time") == "" {
		t.Errorf("Expected X-Custom-Time header to be set")
	}
	if req.Header.Get("X-Custom-Nonce") == "" {
		t.Errorf("Expected X-Custom-Nonce header to be set")
	}
}

func TestAuthConfig_calculateHMACSignature(t *testing.T) {
	config := &AuthConfig{
		Secret: NewSecureString("test-secret"),
	}

	timestamp := int64(1704067200) // Fixed timestamp for testing
	method := "POST"
	path := "/api/auth"
	body := []byte(`{"test":"data"}`)

	signature := config.calculateHMACSignature(timestamp, method, path, body)

	// Calculate expected signature manually
	message := "1704067200POST/api/auth{\"test\":\"data\"}"
	h := hmac.New(sha256.New, []byte("test-secret"))
	h.Write([]byte(message))
	expected := hex.EncodeToString(h.Sum(nil))

	if signature != expected {
		t.Errorf("calculateHMACSignature() = %v, want %v", signature, expected)
	}

	// Verify signature is consistent
	signature2 := config.calculateHMACSignature(timestamp, method, path, body)
	if signature != signature2 {
		t.Errorf("Signature is not consistent: %v != %v", signature, signature2)
	}
}

func TestAuthConfig_VerifyHMACSignature(t *testing.T) {
	config := &AuthConfig{
		Mode:   AuthModeHMAC,
		Secret: NewSecureString("test-secret"),
	}

	body := []byte(`{"username":"test"}`)
	timestamp := time.Now().Unix()
	signature := config.calculateHMACSignature(timestamp, "POST", "/api/auth", body)

	// Create a request with valid signature
	req, err := http.NewRequestWithContext(
		context.Background(),
		"POST",
		testExampleAuthURL,
		bytes.NewBuffer(body),
	)
	if err != nil {
		t.Fatalf("Failed to create request: %v", err)
	}

	req.Header.Set(testXSignature, signature)
	req.Header.Set(testXTimestamp, strconv.FormatInt(timestamp, 10))

	err = config.Verify(req)
	if err != nil {
		t.Errorf("Verify() error = %v, want nil", err)
	}
}

func TestAuthConfig_VerifyHMACSignature_InvalidSignature(t *testing.T) {
	config := &AuthConfig{
		Mode:   AuthModeHMAC,
		Secret: NewSecureString("test-secret"),
	}

	body := []byte(`{"username":"test"}`)
	timestamp := time.Now().Unix()

	// Create a request with invalid signature
	req, err := http.NewRequestWithContext(
		context.Background(),
		"POST",
		testExampleAuthURL,
		bytes.NewBuffer(body),
	)
	if err != nil {
		t.Fatalf("Failed to create request: %v", err)
	}

	req.Header.Set(testXSignature, "invalid-signature-12345")
	req.Header.Set(testXTimestamp, strconv.FormatInt(timestamp, 10))

	err = config.Verify(req)
	if err == nil {
		t.Errorf("VerifyHMACSignature() error = nil, want error")
	}
}

func TestAuthConfig_VerifyHMACSignature_ExpiredTimestamp(t *testing.T) {
	config := &AuthConfig{
		Mode:   AuthModeHMAC,
		Secret: NewSecureString("test-secret"),
	}

	body := []byte(`{"username":"test"}`)
	// Timestamp from 10 minutes ago
	timestamp := time.Now().Add(-10 * time.Minute).Unix()
	signature := config.calculateHMACSignature(timestamp, "POST", "/api/auth", body)

	req, err := http.NewRequestWithContext(
		context.Background(),
		"POST",
		testExampleAuthURL,
		bytes.NewBuffer(body),
	)
	if err != nil {
		t.Fatalf("Failed to create request: %v", err)
	}

	req.Header.Set(testXSignature, signature)
	req.Header.Set(testXTimestamp, strconv.FormatInt(timestamp, 10))

	// Verify with 5 minute max age - should fail
	err = config.Verify(req)
	if err == nil {
		t.Errorf("VerifyHMACSignature() error = nil, want expired error")
	}
}

func TestAuthConfig_VerifyHMACSignature_MissingHeaders(t *testing.T) {
	config := &AuthConfig{
		Mode:   AuthModeHMAC,
		Secret: NewSecureString("test-secret"),
	}

	tests := []struct {
		name      string
		setupReq  func() *http.Request
		wantError bool
	}{
		{
			name: "Missing signature header",
			setupReq: func() *http.Request {
				req, _ := http.NewRequestWithContext(
					context.Background(),
					"POST",
					testExampleURL,
					bytes.NewBufferString("test"),
				)
				req.Header.Set(testXTimestamp, strconv.FormatInt(time.Now().Unix(), 10))
				return req
			},
			wantError: true,
		},
		{
			name: "Missing timestamp header",
			setupReq: func() *http.Request {
				req, _ := http.NewRequestWithContext(
					context.Background(),
					"POST",
					testExampleURL,
					bytes.NewBufferString("test"),
				)
				req.Header.Set(testXSignature, "some-signature")
				return req
			},
			wantError: true,
		},
		{
			name: "Both headers present",
			setupReq: func() *http.Request {
				body := []byte("test")
				req, _ := http.NewRequestWithContext(
					context.Background(),
					"POST",
					testExampleURL,
					bytes.NewBuffer(body),
				)
				timestamp := time.Now().Unix()
				signature := config.calculateHMACSignature(timestamp, "POST", "/api", body)
				req.Header.Set(testXSignature, signature)
				req.Header.Set(testXTimestamp, strconv.FormatInt(timestamp, 10))
				return req
			},
			wantError: false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			req := tt.setupReq()
			// Need to read body first to recreate it for verification
			bodyBytes, _ := io.ReadAll(req.Body)
			req.Body = io.NopCloser(bytes.NewBuffer(bodyBytes))

			err := config.Verify(req)
			if (err != nil) != tt.wantError {
				t.Errorf("VerifyHMACSignature() error = %v, wantError %v", err, tt.wantError)
			}
		})
	}
}

func TestNewAuthConfig(t *testing.T) {
	config := NewAuthConfig("hmac", "my-secret")

	if config.Mode != "hmac" {
		t.Errorf("Mode = %v, want hmac", config.Mode)
	}

	if string(config.Secret.Bytes()) != "my-secret" {
		t.Errorf("Secret = %v, want my-secret", config.Secret)
	}

	// Check defaults
	if config.HeaderName != testXAPISecret {
		t.Errorf("HeaderName = %v, want %s", config.HeaderName, testXAPISecret)
	}

	if config.SignatureHeader != testXSignature {
		t.Errorf("SignatureHeader = %v, want %s", config.SignatureHeader, testXSignature)
	}

	if config.TimestampHeader != testXTimestamp {
		t.Errorf("TimestampHeader = %v, want %s", config.TimestampHeader, testXTimestamp)
	}

	if config.NonceHeader != testXNonce {
		t.Errorf("NonceHeader = %v, want %s", config.NonceHeader, testXNonce)
	}
}

// TestAuthConfig_VerifyHMACSignature_BodyPreservation tests that the request body
// can be read again after VerifyHMACSignature has been called.
// This is critical for middleware scenarios where the body needs to be processed
// by subsequent handlers after signature verification.
func TestAuthConfig_VerifyHMACSignature_BodyPreservation(t *testing.T) {
	config := &AuthConfig{
		Mode:   AuthModeHMAC,
		Secret: NewSecureString("test-secret"),
	}

	originalBody := []byte(`{"username":"test","password":"secret123"}`)
	timestamp := time.Now().Unix()
	signature := config.calculateHMACSignature(timestamp, "POST", "/api/auth", originalBody)

	// Create a request with valid signature
	req, err := http.NewRequestWithContext(
		context.Background(),
		"POST",
		testExampleAuthURL,
		bytes.NewBuffer(originalBody),
	)
	if err != nil {
		t.Fatalf("Failed to create request: %v", err)
	}

	req.Header.Set(testXSignature, signature)
	req.Header.Set(testXTimestamp, strconv.FormatInt(timestamp, 10))

	// Verify the signature (this will read the body)
	err = config.Verify(req)
	if err != nil {
		t.Fatalf("VerifyHMACSignature() error = %v, want nil", err)
	}

	// Try to read the body again (simulating what a subsequent handler would do)
	bodyAfterVerify, err := io.ReadAll(req.Body)
	if err != nil {
		t.Fatalf("Failed to read body after verification: %v", err)
	}

	// The body should still contain the original data
	if !bytes.Equal(bodyAfterVerify, originalBody) {
		t.Errorf(
			"Body after verification = %q, want %q",
			string(bodyAfterVerify),
			string(originalBody),
		)
		t.Errorf(
			"Body length after verification = %d, want %d",
			len(bodyAfterVerify),
			len(originalBody),
		)
		if len(bodyAfterVerify) == 0 {
			t.Error("Body is empty after verification - this proves the bug exists!")
		}
	}
}

// TestAuthConfig_VerifyHMACSignature_FutureTimestamp tests that timestamps
// that are too far in the future are rejected. This prevents clock skew attacks
// where an attacker could send a request with a future timestamp.
func TestAuthConfig_VerifyHMACSignature_FutureTimestamp(t *testing.T) {
	config := &AuthConfig{
		Mode:   AuthModeHMAC,
		Secret: NewSecureString("test-secret"),
	}

	body := []byte(`{"username":"test"}`)
	// Timestamp from 10 minutes in the future
	timestamp := time.Now().Add(10 * time.Minute).Unix()
	signature := config.calculateHMACSignature(timestamp, "POST", "/api/auth", body)

	req, err := http.NewRequestWithContext(
		context.Background(),
		"POST",
		testExampleAuthURL,
		bytes.NewBuffer(body),
	)
	if err != nil {
		t.Fatalf("Failed to create request: %v", err)
	}

	req.Header.Set(testXSignature, signature)
	req.Header.Set(testXTimestamp, strconv.FormatInt(timestamp, 10))

	// Verify with 5 minute max age - should fail for future timestamp
	err = config.Verify(req)
	if err == nil {
		t.Error("VerifyHMACSignature() error = nil, want future timestamp error")
		t.Error("SECURITY VULNERABILITY: Request with future timestamp was accepted!")
		t.Error("An attacker could use clock skew attacks to:")
		t.Error("  - Bypass timestamp expiration by sending far-future timestamps")
		t.Error("  - Reuse the same signature for an extended period")
		t.Errorf("Request timestamp: %d (10 minutes in the future)", timestamp)
		t.Errorf("Current time: %d", time.Now().Unix())
	} else {
		t.Logf("Good! Verification correctly failed: %v", err)
	}
}

// TestAuthConfig_VerifyHMACSignature_QueryParameterSecurity tests that query parameters
// are included in the HMAC signature calculation. Without this, an attacker could modify
// query parameters without invalidating the signature, which is a security vulnerability.
func TestAuthConfig_VerifyHMACSignature_QueryParameterSecurity(t *testing.T) {
	config := &AuthConfig{
		Mode:   AuthModeHMAC,
		Secret: NewSecureString("test-secret"),
	}

	body := []byte(`{"action":"view"}`)
	timestamp := time.Now().Unix()

	// Step 1: Create signature for original request with safe query parameters
	originalURL := "http://example.com/api/users?id=123&action=view"
	req1, _ := http.NewRequestWithContext(
		context.Background(),
		"POST",
		originalURL,
		bytes.NewBuffer(body),
	)

	// Generate signature using the SAME logic as VerifyHMACSignature
	// (which now includes query parameters)
	fullPath := req1.URL.Path
	if req1.URL.RawQuery != "" {
		fullPath += "?" + req1.URL.RawQuery
	}
	signature := config.calculateHMACSignature(timestamp, req1.Method, fullPath, body)

	// Verify original request passes
	req1.Header.Set(testXSignature, signature)
	req1.Header.Set(testXTimestamp, strconv.FormatInt(timestamp, 10))
	if err := config.Verify(req1); err != nil {
		t.Fatalf("Original request should pass verification: %v", err)
	}

	// Step 2: Create a DIFFERENT request with MALICIOUS query parameters
	// but use the SAME signature from step 1
	maliciousURL := "http://example.com/api/users?id=999&action=delete&admin=true"
	req2, _ := http.NewRequestWithContext(
		context.Background(),
		"POST",
		maliciousURL,
		bytes.NewBuffer(body),
	)

	// Use the SAME signature (from original safe request)
	req2.Header.Set(testXSignature, signature)
	req2.Header.Set(testXTimestamp, strconv.FormatInt(timestamp, 10))

	// Verify the tampered request
	err := config.Verify(req2)

	// This SHOULD fail because query params are different
	// If it passes, it means query params are NOT included in signature (security bug)
	if err == nil {
		t.Error(
			"SECURITY VULNERABILITY: VerifyHMACSignature() passed with tampered query parameters!",
		)
		t.Error("This proves that query parameters are NOT included in the signature calculation.")
		t.Errorf("Original request: %s", originalURL)
		t.Errorf("Tampered request: %s", maliciousURL)
		t.Error("An attacker could:")
		t.Error("  - Change user IDs to access other users' data")
		t.Error("  - Change actions from 'view' to 'delete'")
		t.Error("  - Add admin privileges")
		t.Error("All without invalidating the signature!")
	} else {
		t.Logf("Good! Verification correctly failed: %v", err)
	}
}

// TestAuthConfig_VerifyHMACSignature_BodySizeLimit_WithinLimit tests that
// requests with body size within the limit are accepted.
func TestAuthConfig_VerifyHMACSignature_BodySizeLimit_WithinLimit(t *testing.T) {
	config := &AuthConfig{
		Mode:   AuthModeHMAC,
		Secret: NewSecureString("test-secret"),
	}

	// Create a body that's 1KB (well within 10MB default limit)
	body := bytes.Repeat([]byte("a"), 1024)
	timestamp := time.Now().Unix()
	signature := config.calculateHMACSignature(timestamp, "POST", "/api/data", body)

	req, err := http.NewRequestWithContext(
		context.Background(),
		"POST",
		"http://example.com/api/data",
		bytes.NewBuffer(body),
	)
	if err != nil {
		t.Fatalf("Failed to create request: %v", err)
	}

	req.Header.Set(testXSignature, signature)
	req.Header.Set(testXTimestamp, strconv.FormatInt(timestamp, 10))

	// Use default 10MB limit
	err = config.Verify(req)
	if err != nil {
		t.Errorf("VerifyHMACSignature() error = %v, want nil for body within limit", err)
	}
}

// TestAuthConfig_VerifyHMACSignature_BodySizeLimit_ExceedsLimit tests that
// requests with body size exceeding the limit are rejected.
func TestAuthConfig_VerifyHMACSignature_BodySizeLimit_ExceedsLimit(t *testing.T) {
	config := &AuthConfig{
		Mode:   AuthModeHMAC,
		Secret: NewSecureString("test-secret"),
	}

	// Create a body that's 2KB
	body := bytes.Repeat([]byte("a"), 2048)
	timestamp := time.Now().Unix()
	signature := config.calculateHMACSignature(timestamp, "POST", "/api/data", body)

	req, err := http.NewRequestWithContext(
		context.Background(),
		"POST",
		"http://example.com/api/data",
		bytes.NewBuffer(body),
	)
	if err != nil {
		t.Fatalf("Failed to create request: %v", err)
	}

	req.Header.Set(testXSignature, signature)
	req.Header.Set(testXTimestamp, strconv.FormatInt(timestamp, 10))

	// Set limit to 1KB (1024 bytes) - body is 2KB, should fail
	maxBodySize := int64(1024)
	err = config.Verify(req, WithVerifyMaxBodySize(maxBodySize))
	if err == nil {
		t.Error("VerifyHMACSignature() error = nil, want body size error")
		t.Error("SECURITY VULNERABILITY: Large body was accepted despite size limit!")
		t.Errorf("Body size: %d bytes, Limit: %d bytes", len(body), maxBodySize)
	}

	// Verify error message contains size information
	if err != nil && !strings.Contains(err.Error(), "too large") {
		t.Errorf("Error message should mention size limit, got: %v", err)
	}
}

// TestAuthConfig_VerifyHMACSignature_BodySizeLimit_ExactLimit tests that
// requests with body size exactly at the limit are accepted.
func TestAuthConfig_VerifyHMACSignature_BodySizeLimit_ExactLimit(t *testing.T) {
	config := &AuthConfig{
		Mode:   AuthModeHMAC,
		Secret: NewSecureString("test-secret"),
	}

	// Create a body that's exactly 1KB
	body := bytes.Repeat([]byte("a"), 1024)
	timestamp := time.Now().Unix()
	signature := config.calculateHMACSignature(timestamp, "POST", "/api/data", body)

	req, err := http.NewRequestWithContext(
		context.Background(),
		"POST",
		"http://example.com/api/data",
		bytes.NewBuffer(body),
	)
	if err != nil {
		t.Fatalf("Failed to create request: %v", err)
	}

	req.Header.Set(testXSignature, signature)
	req.Header.Set(testXTimestamp, strconv.FormatInt(timestamp, 10))

	// Set limit to exactly 1KB
	maxBodySize := int64(1024)
	err = config.Verify(req, WithVerifyMaxBodySize(maxBodySize))
	if err != nil {
		t.Errorf("VerifyHMACSignature() error = %v, want nil for body at exact limit", err)
	}
}

// TestAuthConfig_VerifyHMACSignature_BodySizeLimit_DefaultLimit tests that
// the default 10MB limit is applied when no options are provided.
func TestAuthConfig_VerifyHMACSignature_BodySizeLimit_DefaultLimit(t *testing.T) {
	config := &AuthConfig{
		Mode:   AuthModeHMAC,
		Secret: NewSecureString("test-secret"),
	}

	// Create a body that's 5MB (should pass with 10MB default)
	body := bytes.Repeat([]byte("a"), 5*1024*1024)
	timestamp := time.Now().Unix()
	signature := config.calculateHMACSignature(timestamp, "POST", "/api/data", body)

	req, err := http.NewRequestWithContext(
		context.Background(),
		"POST",
		"http://example.com/api/data",
		bytes.NewBuffer(body),
	)
	if err != nil {
		t.Fatalf("Failed to create request: %v", err)
	}

	req.Header.Set(testXSignature, signature)
	req.Header.Set(testXTimestamp, strconv.FormatInt(timestamp, 10))

	// Use default limit (no options)
	err = config.Verify(req)
	if err != nil {
		t.Errorf("VerifyHMACSignature() error = %v, want nil with default 10MB limit", err)
	}

	// Now test with 11MB body (should fail with default 10MB limit)
	largeBody := bytes.Repeat([]byte("b"), 11*1024*1024)
	largeSignature := config.calculateHMACSignature(timestamp, "POST", "/api/data", largeBody)

	req2, err := http.NewRequestWithContext(
		context.Background(),
		"POST",
		"http://example.com/api/data",
		bytes.NewBuffer(largeBody),
	)
	if err != nil {
		t.Fatalf("Failed to create request: %v", err)
	}

	req2.Header.Set(testXSignature, largeSignature)
	req2.Header.Set(testXTimestamp, strconv.FormatInt(timestamp, 10))

	err = config.Verify(req2)
	if err == nil {
		t.Error("VerifyHMACSignature() should reject 11MB body with default 10MB limit")
	}
}

// TestAuthConfig_VerifyHMACSignature_MultipleOptions tests that
// multiple options can be combined using the Option Pattern.
func TestAuthConfig_VerifyHMACSignature_MultipleOptions(t *testing.T) {
	config := &AuthConfig{
		Mode:   AuthModeHMAC,
		Secret: NewSecureString("test-secret"),
	}

	body := []byte(`{"test":"data"}`)
	timestamp := time.Now().Unix()
	signature := config.calculateHMACSignature(timestamp, "POST", "/api/data", body)

	req, err := http.NewRequestWithContext(
		context.Background(),
		"POST",
		"http://example.com/api/data",
		bytes.NewBuffer(body),
	)
	if err != nil {
		t.Fatalf("Failed to create request: %v", err)
	}

	req.Header.Set(testXSignature, signature)
	req.Header.Set(testXTimestamp, strconv.FormatInt(timestamp, 10))

	// Combine multiple options
	err = config.Verify(req,
		WithVerifyMaxAge(10*time.Minute),
		WithVerifyMaxBodySize(1024),
	)
	if err != nil {
		t.Errorf("VerifyHMACSignature() with multiple options error = %v, want nil", err)
	}
}

// TestAuthConfig_VerifySimpleAuth tests simple authentication verification.
func TestAuthConfig_VerifySimpleAuth(t *testing.T) {
	tests := []struct {
		name       string
		config     *AuthConfig
		headerName string
		secret     string
		wantErr    bool
		errMsg     string
	}{
		{
			name: "Valid secret with default header",
			config: &AuthConfig{
				Secret: NewSecureString("test-secret-123"),
			},
			headerName: "X-API-Secret",
			secret:     "test-secret-123",
			wantErr:    false,
		},
		{
			name: "Valid secret with custom header",
			config: &AuthConfig{
				Secret:     NewSecureString("my-custom-secret"),
				HeaderName: "X-Custom-Auth",
			},
			headerName: "X-Custom-Auth",
			secret:     "my-custom-secret",
			wantErr:    false,
		},
		{
			name: "Invalid secret",
			config: &AuthConfig{
				Secret: NewSecureString("correct-secret"),
			},
			headerName: "X-API-Secret",
			secret:     "wrong-secret",
			wantErr:    true,
			errMsg:     "authentication failed",
		},
		{
			name: "Missing header",
			config: &AuthConfig{
				Secret: NewSecureString("test-secret"),
			},
			headerName: "X-API-Secret",
			secret:     "",
			wantErr:    true,
			errMsg:     "missing authentication header",
		},
		{
			name: "Empty secret in config",
			config: &AuthConfig{
				Secret: NewSecureString(""),
			},
			headerName: "X-API-Secret",
			secret:     "some-secret",
			wantErr:    true,
			errMsg:     "secret is required",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			req, err := http.NewRequestWithContext(
				context.Background(),
				"GET",
				testExampleURL,
				nil,
			)
			if err != nil {
				t.Fatalf("Failed to create request: %v", err)
			}

			if tt.secret != "" {
				req.Header.Set(tt.headerName, tt.secret)
			}

			err = tt.config.verifySimpleAuth(req)
			if (err != nil) != tt.wantErr {
				t.Errorf("VerifySimpleAuth() error = %v, wantErr %v", err, tt.wantErr)
			}

			if tt.wantErr && err != nil && !strings.Contains(err.Error(), tt.errMsg) {
				t.Errorf("VerifySimpleAuth() error = %v, want error containing %q", err, tt.errMsg)
			}
		})
	}
}

// TestAuthConfig_Verify tests the unified verification method.
func TestAuthConfig_Verify(t *testing.T) {
	tests := []struct {
		name    string
		config  *AuthConfig
		setup   func(*http.Request, *AuthConfig)
		wantErr bool
		errMsg  string
	}{
		{
			name: "AuthModeNone - no verification",
			config: &AuthConfig{
				Mode:   AuthModeNone,
				Secret: NewSecureString("test-secret"),
			},
			setup:   func(req *http.Request, c *AuthConfig) {},
			wantErr: false,
		},
		{
			name: "Empty mode - no verification",
			config: &AuthConfig{
				Mode:   "",
				Secret: NewSecureString("test-secret"),
			},
			setup:   func(req *http.Request, c *AuthConfig) {},
			wantErr: false,
		},
		{
			name:    "Nil config - no verification",
			config:  (*AuthConfig)(nil),
			setup:   func(req *http.Request, c *AuthConfig) {},
			wantErr: false,
		},
		{
			name: "AuthModeSimple - valid secret",
			config: &AuthConfig{
				Mode:   AuthModeSimple,
				Secret: NewSecureString("test-secret"),
			},
			setup: func(req *http.Request, c *AuthConfig) {
				req.Header.Set("X-API-Secret", "test-secret")
			},
			wantErr: false,
		},
		{
			name: "AuthModeSimple - invalid secret",
			config: &AuthConfig{
				Mode:   AuthModeSimple,
				Secret: NewSecureString("correct-secret"),
			},
			setup: func(req *http.Request, c *AuthConfig) {
				req.Header.Set("X-API-Secret", "wrong-secret")
			},
			wantErr: true,
			errMsg:  "authentication failed",
		},
		{
			name: "AuthModeHMAC - valid signature",
			config: &AuthConfig{
				Mode:   AuthModeHMAC,
				Secret: NewSecureString("hmac-secret"),
			},
			setup: func(req *http.Request, c *AuthConfig) {
				body := []byte(`{"test":"data"}`)
				timestamp := time.Now().Unix()
				signature := c.calculateHMACSignature(timestamp, "POST", "/api", body)
				req.Header.Set(testXSignature, signature)
				req.Header.Set(testXTimestamp, strconv.FormatInt(timestamp, 10))
				req.Body = io.NopCloser(bytes.NewBuffer(body))
			},
			wantErr: false,
		},
		{
			name: "AuthModeHMAC - invalid signature",
			config: &AuthConfig{
				Mode:   AuthModeHMAC,
				Secret: NewSecureString("hmac-secret"),
			},
			setup: func(req *http.Request, c *AuthConfig) {
				body := []byte(`{"test":"data"}`)
				timestamp := time.Now().Unix()
				req.Header.Set(testXSignature, "invalid-signature")
				req.Header.Set(testXTimestamp, strconv.FormatInt(timestamp, 10))
				req.Body = io.NopCloser(bytes.NewBuffer(body))
			},
			wantErr: true,
			errMsg:  "signature verification failed",
		},
		{
			name: "Unsupported mode",
			config: &AuthConfig{
				Mode:   "unsupported-mode",
				Secret: NewSecureString("test-secret"),
			},
			setup:   func(req *http.Request, c *AuthConfig) {},
			wantErr: true,
			errMsg:  "unsupported authentication mode",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			req, err := http.NewRequestWithContext(
				context.Background(),
				"POST",
				testExampleURL,
				nil,
			)
			if err != nil {
				t.Fatalf("Failed to create request: %v", err)
			}

			if tt.setup != nil {
				tt.setup(req, tt.config)
			}

			err = tt.config.Verify(req)
			if (err != nil) != tt.wantErr {
				t.Errorf("Verify() error = %v, wantErr %v", err, tt.wantErr)
			}

			if tt.wantErr && err != nil && tt.errMsg != "" &&
				!strings.Contains(err.Error(), tt.errMsg) {
				t.Errorf("Verify() error = %v, want error containing %q", err, tt.errMsg)
			}
		})
	}
}

// TestAuthConfig_Verify_WithOptions tests Verify with VerifyOptions for HMAC mode.
func TestAuthConfig_Verify_WithOptions(t *testing.T) {
	config := &AuthConfig{
		Mode:   AuthModeHMAC,
		Secret: NewSecureString("test-secret"),
	}

	body := []byte(`{"test":"data"}`)
	timestamp := time.Now().Unix()
	signature := config.calculateHMACSignature(timestamp, "POST", "/api/data", body)

	req, err := http.NewRequestWithContext(
		context.Background(),
		"POST",
		"http://example.com/api/data",
		bytes.NewBuffer(body),
	)
	if err != nil {
		t.Fatalf("Failed to create request: %v", err)
	}

	req.Header.Set(testXSignature, signature)
	req.Header.Set(testXTimestamp, strconv.FormatInt(timestamp, 10))

	// Test with options
	err = config.Verify(req,
		WithVerifyMaxAge(10*time.Minute),
		WithVerifyMaxBodySize(1024),
	)
	if err != nil {
		t.Errorf("Verify() with options error = %v, want nil", err)
	}
}

// TestAuthConfig_VerifyGitHubSignature_Success tests successful GitHub signature verification.
func TestAuthConfig_VerifyGitHubSignature_Success(t *testing.T) {
	secret := testAPISecret
	body := `{"action":"opened","number":123}`

	// Create request
	req, err := http.NewRequestWithContext(
		context.Background(),
		"POST",
		"/webhook",
		strings.NewReader(body),
	)
	if err != nil {
		t.Fatalf("Failed to create request: %v", err)
	}

	// Calculate correct signature
	h := hmac.New(sha256.New, []byte(secret))
	h.Write([]byte(body))
	signature := "sha256=" + hex.EncodeToString(h.Sum(nil))
	req.Header.Set("X-Hub-Signature-256", signature)

	// Verify
	auth := NewAuthConfig(AuthModeGitHub, secret)
	err = auth.Verify(req)
	if err != nil {
		t.Errorf("Verify() error = %v, want nil", err)
	}
}

// TestAuthConfig_VerifyGitHubSignature_InvalidSignature tests rejection of invalid signatures.
func TestAuthConfig_VerifyGitHubSignature_InvalidSignature(t *testing.T) {
	secret := testAPISecret
	body := `{"action":"opened"}`

	req, err := http.NewRequestWithContext(
		context.Background(),
		"POST",
		"/webhook",
		strings.NewReader(body),
	)
	if err != nil {
		t.Fatalf("Failed to create request: %v", err)
	}
	req.Header.Set("X-Hub-Signature-256", "sha256=invalid_signature")

	auth := NewAuthConfig(AuthModeGitHub, secret)
	err = auth.Verify(req)

	if err == nil {
		t.Error("Verify() error = nil, want error")
	}
	if err != nil && !strings.Contains(err.Error(), "signature verification failed") {
		t.Errorf("Verify() error = %v, want error containing 'signature verification failed'", err)
	}
}

// TestAuthConfig_VerifyGitHubSignature_MissingHeader tests rejection when signature header is missing.
func TestAuthConfig_VerifyGitHubSignature_MissingHeader(t *testing.T) {
	body := `{"test":"data"}` //nolint:goconst // test data
	req, err := http.NewRequestWithContext(
		context.Background(),
		"POST",
		"/webhook",
		strings.NewReader(body),
	)
	if err != nil {
		t.Fatalf("Failed to create request: %v", err)
	}

	auth := NewAuthConfig(AuthModeGitHub, "secret")
	err = auth.Verify(req)

	if err == nil {
		t.Error("Verify() error = nil, want error")
	}
	if err != nil && !strings.Contains(err.Error(), "missing X-Hub-Signature-256 header") {
		t.Errorf(
			"Verify() error = %v, want error containing 'missing X-Hub-Signature-256 header'",
			err,
		)
	}
}

// TestAuthConfig_VerifyGitHubSignature_MalformedSignature tests rejection of malformed signatures.
func TestAuthConfig_VerifyGitHubSignature_MalformedSignature(t *testing.T) {
	body := `{"test":"data"}`
	req, err := http.NewRequestWithContext(
		context.Background(),
		"POST",
		"/webhook",
		strings.NewReader(body),
	)
	if err != nil {
		t.Fatalf("Failed to create request: %v", err)
	}
	req.Header.Set("X-Hub-Signature-256", "abcdef1234567890") // No "sha256=" prefix

	auth := NewAuthConfig(AuthModeGitHub, "secret")
	err = auth.Verify(req)

	if err == nil {
		t.Error("Verify() error = nil, want error")
	}
	if err != nil && !strings.Contains(err.Error(), "invalid signature format") {
		t.Errorf("Verify() error = %v, want error containing 'invalid signature format'", err)
	}
}

// TestAuthConfig_VerifyGitHubSignature_BodyPreservation tests that body can be read after verification.
func TestAuthConfig_VerifyGitHubSignature_BodyPreservation(t *testing.T) {
	secret := testAPISecret
	body := `{"test":"data"}`

	req, err := http.NewRequestWithContext(
		context.Background(),
		"POST",
		"/webhook",
		strings.NewReader(body),
	)
	if err != nil {
		t.Fatalf("Failed to create request: %v", err)
	}

	// Correct signature
	h := hmac.New(sha256.New, []byte(secret))
	h.Write([]byte(body))
	signature := "sha256=" + hex.EncodeToString(h.Sum(nil))
	req.Header.Set("X-Hub-Signature-256", signature)

	// Verify
	auth := NewAuthConfig(AuthModeGitHub, secret)
	err = auth.Verify(req)
	if err != nil {
		t.Fatalf("Verify() error = %v, want nil", err)
	}

	// Read body after verification
	bodyBytes, err := io.ReadAll(req.Body)
	if err != nil {
		t.Fatalf("Failed to read body: %v", err)
	}
	if string(bodyBytes) != body {
		t.Errorf("Body after verification = %q, want %q", string(bodyBytes), body)
	}
}

// TestAuthConfig_VerifyGitHubSignature_EmptyBody tests that empty body is valid.
func TestAuthConfig_VerifyGitHubSignature_EmptyBody(t *testing.T) {
	secret := testAPISecret
	body := ""

	req, err := http.NewRequestWithContext(
		context.Background(),
		"POST",
		"/webhook",
		strings.NewReader(body),
	)
	if err != nil {
		t.Fatalf("Failed to create request: %v", err)
	}

	h := hmac.New(sha256.New, []byte(secret))
	h.Write([]byte(body))
	signature := "sha256=" + hex.EncodeToString(h.Sum(nil))
	req.Header.Set("X-Hub-Signature-256", signature)

	auth := NewAuthConfig(AuthModeGitHub, secret)
	err = auth.Verify(req)
	if err != nil {
		t.Errorf("Verify() error = %v, want nil", err)
	}
}

// TestAuthConfig_VerifyGitHubSignature_BodyTooLarge tests rejection of oversized bodies.
func TestAuthConfig_VerifyGitHubSignature_BodyTooLarge(t *testing.T) {
	secret := testAPISecret
	body := strings.Repeat("x", 11*1024*1024) // 11MB > 10MB default limit

	req, err := http.NewRequestWithContext(
		context.Background(),
		"POST",
		"/webhook",
		strings.NewReader(body),
	)
	if err != nil {
		t.Fatalf("Failed to create request: %v", err)
	}
	req.Header.Set("X-Hub-Signature-256", "sha256=dummy")

	auth := NewAuthConfig(AuthModeGitHub, secret)
	err = auth.Verify(req)

	if err == nil {
		t.Error("Verify() error = nil, want error")
	}
	if err != nil && !strings.Contains(err.Error(), "request body too large") {
		t.Errorf("Verify() error = %v, want error containing 'request body too large'", err)
	}
}

// TestAuthConfig_VerifyGitHubSignature_CustomBodyLimit tests custom body size limit.
func TestAuthConfig_VerifyGitHubSignature_CustomBodyLimit(t *testing.T) {
	secret := testAPISecret
	body := strings.Repeat("x", 3*1024) // 3KB

	req, err := http.NewRequestWithContext(
		context.Background(),
		"POST",
		"/webhook",
		strings.NewReader(body),
	)
	if err != nil {
		t.Fatalf("Failed to create request: %v", err)
	}

	h := hmac.New(sha256.New, []byte(secret))
	h.Write([]byte(body))
	signature := "sha256=" + hex.EncodeToString(h.Sum(nil))
	req.Header.Set("X-Hub-Signature-256", signature)

	auth := NewAuthConfig(AuthModeGitHub, secret)
	err = auth.Verify(req, WithVerifyMaxBodySize(2*1024)) // 2KB limit

	if err == nil {
		t.Error("Verify() error = nil, want error")
	}
	if err != nil && !strings.Contains(err.Error(), "request body too large") {
		t.Errorf("Verify() error = %v, want error containing 'request body too large'", err)
	}
}

// TestAuthConfig_VerifyGitHubSignature_EmptySecret tests rejection when secret is empty.
func TestAuthConfig_VerifyGitHubSignature_EmptySecret(t *testing.T) {
	body := `{"test":"data"}`
	req, err := http.NewRequestWithContext(
		context.Background(),
		"POST",
		"/webhook",
		strings.NewReader(body),
	)
	if err != nil {
		t.Fatalf("Failed to create request: %v", err)
	}
	req.Header.Set("X-Hub-Signature-256", "sha256=abc")

	auth := NewAuthConfig(AuthModeGitHub, "") // Empty secret
	err = auth.Verify(req)

	if err == nil {
		t.Error("Verify() error = nil, want error")
	}
	if err != nil && !strings.Contains(err.Error(), "secret is required") {
		t.Errorf("Verify() error = %v, want error containing 'secret is required'", err)
	}
}

// TestAuthConfig_AddGitHubAuth_Success tests client-side GitHub signature addition.
func TestAuthConfig_AddGitHubAuth_Success(t *testing.T) {
	secret := testAPISecret
	body := []byte(`{"test":"data"}`)

	req, err := http.NewRequestWithContext(
		context.Background(),
		"POST",
		"/webhook",
		bytes.NewReader(body),
	)
	if err != nil {
		t.Fatalf("Failed to create request: %v", err)
	}
	auth := NewAuthConfig(AuthModeGitHub, secret)

	err = auth.addGitHubAuth(req, body)
	if err != nil {
		t.Errorf("addGitHubAuth() error = %v, want nil", err)
	}

	// Verify header
	signature := req.Header.Get("X-Hub-Signature-256")
	if signature == "" {
		t.Error("X-Hub-Signature-256 header is empty")
	}
	if !strings.HasPrefix(signature, "sha256=") {
		t.Errorf("Signature = %q, want prefix 'sha256='", signature)
	}

	// Verify signature correctness
	h := hmac.New(sha256.New, []byte(secret))
	h.Write(body)
	expected := "sha256=" + hex.EncodeToString(h.Sum(nil))
	if signature != expected {
		t.Errorf("Signature = %q, want %q", signature, expected)
	}
}

// TestAuthConfig_AddGitHubAuth_EmptySecret tests error when secret is empty.
func TestAuthConfig_AddGitHubAuth_EmptySecret(t *testing.T) {
	body := []byte(`{"test":"data"}`)
	req, err := http.NewRequestWithContext(
		context.Background(),
		"POST",
		"/webhook",
		bytes.NewReader(body),
	)
	if err != nil {
		t.Fatalf("Failed to create request: %v", err)
	}

	auth := NewAuthConfig(AuthModeGitHub, "")
	err = auth.addGitHubAuth(req, body)

	if err == nil {
		t.Error("addGitHubAuth() error = nil, want error")
	}
	if err != nil && !strings.Contains(err.Error(), "secret is required") {
		t.Errorf("addGitHubAuth() error = %v, want error containing 'secret is required'", err)
	}
}

// TestAuthConfig_GitHubMode_EndToEnd tests end-to-end client signing and server verification.
func TestAuthConfig_GitHubMode_EndToEnd(t *testing.T) {
	secret := testAPISecret
	payload := []byte(`{"action":"opened","pull_request":{"id":123}}`)

	// Create test server with GitHub verification
	serverConfig := NewAuthConfig(AuthModeGitHub, secret)
	server := http.NewServeMux()
	server.HandleFunc("/webhook", func(w http.ResponseWriter, r *http.Request) {
		// Verify signature
		if err := serverConfig.Verify(r); err != nil {
			http.Error(w, err.Error(), http.StatusUnauthorized)
			return
		}

		// Read body after verification
		body, _ := io.ReadAll(r.Body)
		w.WriteHeader(http.StatusOK)
		_, _ = w.Write(body)
	})

	// #nosec G112 - ReadHeaderTimeout not needed for test server
	ts := http.Server{Handler: server}
	// #nosec G102 - Binding to localhost (":0") is safe for test server
	lc := net.ListenConfig{}
	listener, err := lc.Listen(context.Background(), "tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("Failed to listen: %v", err)
	}
	defer listener.Close()

	go func() {
		_ = ts.Serve(listener)
	}()
	defer func() {
		_ = ts.Shutdown(context.Background())
	}()

	// Give server time to start
	time.Sleep(10 * time.Millisecond)

	// Create client
	client, err := NewAuthClient(AuthModeGitHub, secret)
	if err != nil {
		t.Fatalf("Failed to create client: %v", err)
	}

	// Create and send request
	req, _ := http.NewRequestWithContext(
		context.Background(),
		http.MethodPost,
		"http://"+listener.Addr().String()+"/webhook",
		bytes.NewReader(payload),
	)
	req.Header.Set("Content-Type", "application/json")

	resp, err := client.Do(req)
	if err != nil {
		t.Fatalf("Request failed: %v", err)
	}
	defer resp.Body.Close()

	// Verify response
	if resp.StatusCode != http.StatusOK {
		body, _ := io.ReadAll(resp.Body)
		t.Errorf(
			"Response status = %d, want %d. Body: %s",
			resp.StatusCode,
			http.StatusOK,
			string(body),
		)
	}

	// Verify response body matches
	respBody, _ := io.ReadAll(resp.Body)
	if !bytes.Equal(respBody, payload) {
		t.Errorf("Response body = %q, want %q", string(respBody), string(payload))
	}
}

// TestAuthConfig_GitHubMode_PythonCompatibility tests compatibility with Python HMAC implementation.
func TestAuthConfig_GitHubMode_PythonCompatibility(t *testing.T) {
	// Test vectors that would match Python's implementation:
	// hmac.new(b'test-webhook-secret', msg=b'{"action":"opened","number":42}', digestmod=hashlib.sha256).hexdigest()
	// #nosec G101 - Hardcoded secret is intentional for test
	secret := "test-webhook-secret"
	payload := `{"action":"opened","number":42}`

	// Go calculation
	h := hmac.New(sha256.New, []byte(secret))
	h.Write([]byte(payload))
	goSignature := "sha256=" + hex.EncodeToString(h.Sum(nil))

	// Create request
	req, err := http.NewRequestWithContext(
		context.Background(),
		"POST",
		"/webhook",
		strings.NewReader(payload),
	)
	if err != nil {
		t.Fatalf("Failed to create request: %v", err)
	}
	req.Header.Set("X-Hub-Signature-256", goSignature)

	// Verify
	auth := NewAuthConfig(AuthModeGitHub, secret)
	err = auth.Verify(req)
	if err != nil {
		t.Errorf("Verify() error = %v, want nil (Python-compatible signature failed)", err)
	}
}
