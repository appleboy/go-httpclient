package httpclient

import (
	"bytes"
	"crypto/hmac"
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"io"
	"math"
	"net/http"
	"strconv"
	"strings"
	"time"

	"github.com/google/uuid"
)

// Authentication mode constants
const (
	AuthModeNone   = "none"   // No authentication
	AuthModeSimple = "simple" // Simple API secret in header
	AuthModeHMAC   = "hmac"   // HMAC-SHA256 signature
	AuthModeGitHub = "github" // GitHub webhook-style HMAC-SHA256 signature
)

// Default header name constants
const (
	DefaultAPISecretHeader       = "X-API-Secret"        // Default header for simple mode
	DefaultSignatureHeader       = "X-Signature"         // Default signature header for HMAC mode
	DefaultTimestampHeader       = "X-Timestamp"         // Default timestamp header for HMAC mode
	DefaultNonceHeader           = "X-Nonce"             // Default nonce header for HMAC mode
	DefaultGitHubSignatureHeader = "X-Hub-Signature-256" // Default signature header for GitHub mode
	DefaultRequestIDHeader       = "X-Request-ID"        // Default request ID header for tracing
)

// Default verification option constants
const (
	DefaultVerifyMaxAge      = 5 * time.Minute  // Default maximum age for request timestamps
	DefaultVerifyMaxBodySize = 10 * 1024 * 1024 // Default maximum request body size (10MB)
)

// AuthConfig holds authentication configuration
type AuthConfig struct {
	Mode            string // "none", "simple", or "hmac"
	Secret          string // Shared secret key
	HeaderName      string // Custom header name for simple mode (default: "X-API-Secret")
	SignatureHeader string // Signature header name for HMAC mode (default: "X-Signature")
	TimestampHeader string // Timestamp header name for HMAC mode (default: "X-Timestamp")
	NonceHeader     string // Nonce header name for HMAC mode (default: "X-Nonce")
}

// VerifyOptions holds options for signature verification
type VerifyOptions struct {
	MaxAge      time.Duration // Maximum age of request timestamp (default: 5 minutes)
	MaxBodySize int64         // Maximum request body size in bytes (default: 10MB)
}

// VerifyOption is a function that configures VerifyOptions
type VerifyOption func(*VerifyOptions)

// defaultVerifyOptions returns default verification options
func defaultVerifyOptions() *VerifyOptions {
	return &VerifyOptions{
		MaxAge:      DefaultVerifyMaxAge,
		MaxBodySize: DefaultVerifyMaxBodySize,
	}
}

// WithVerifyMaxAge sets the maximum age for request timestamps during verification
func WithVerifyMaxAge(d time.Duration) VerifyOption {
	return func(o *VerifyOptions) {
		if d <= 0 {
			// Ignore non-positive values to avoid disabling verification unintentionally.
			return
		}
		o.MaxAge = d
	}
}

// WithVerifyMaxBodySize sets the maximum request body size in bytes during verification
func WithVerifyMaxBodySize(size int64) VerifyOption {
	return func(o *VerifyOptions) {
		if size > 0 {
			o.MaxBodySize = size
		}
	}
}

// NewAuthConfig creates a new AuthConfig with defaults
func NewAuthConfig(mode, secret string) *AuthConfig {
	config := &AuthConfig{
		Mode:            mode,
		Secret:          secret,
		HeaderName:      DefaultAPISecretHeader,
		SignatureHeader: DefaultSignatureHeader,
		TimestampHeader: DefaultTimestampHeader,
		NonceHeader:     DefaultNonceHeader,
	}

	// GitHub mode uses different default header
	if mode == AuthModeGitHub {
		config.SignatureHeader = DefaultGitHubSignatureHeader
	}

	return config
}

// addAuthHeaders adds authentication headers to the HTTP request based on configured mode.
// This is an internal method used by authRoundTripper. External users should use NewAuthClient() instead.
func (c *AuthConfig) addAuthHeaders(req *http.Request, body []byte) error {
	if c == nil || c.Mode == AuthModeNone || c.Mode == "" {
		return nil // No authentication
	}

	switch c.Mode {
	case AuthModeSimple:
		return c.addSimpleAuth(req)
	case AuthModeHMAC:
		return c.addHMACAuth(req, body)
	case AuthModeGitHub:
		return c.addGitHubAuth(req, body)
	default:
		return fmt.Errorf("unsupported authentication mode: %s", c.Mode)
	}
}

// addSimpleAuth adds simple API secret header
func (c *AuthConfig) addSimpleAuth(req *http.Request) error {
	if c.Secret == "" {
		return fmt.Errorf("secret is required for simple authentication")
	}

	headerName := c.HeaderName
	if headerName == "" {
		headerName = DefaultAPISecretHeader
	}

	req.Header.Set(headerName, c.Secret)
	return nil
}

// addHMACAuth adds HMAC signature headers
func (c *AuthConfig) addHMACAuth(req *http.Request, body []byte) error {
	if c.Secret == "" {
		return fmt.Errorf("secret is required for HMAC authentication")
	}

	// Generate timestamp and nonce
	timestamp := time.Now().Unix()
	nonce := uuid.New().String()

	// Calculate signature: HMAC-SHA256(secret, timestamp + method + path + query + body)
	signature := c.calculateHMACSignature(
		timestamp,
		req.Method,
		getFullPath(req),
		body,
	)

	// Set headers
	signatureHeader := c.SignatureHeader
	if signatureHeader == "" {
		signatureHeader = DefaultSignatureHeader
	}

	timestampHeader := c.TimestampHeader
	if timestampHeader == "" {
		timestampHeader = DefaultTimestampHeader
	}

	nonceHeader := c.NonceHeader
	if nonceHeader == "" {
		nonceHeader = DefaultNonceHeader
	}

	req.Header.Set(signatureHeader, signature)
	req.Header.Set(timestampHeader, strconv.FormatInt(timestamp, 10))
	req.Header.Set(nonceHeader, nonce)

	return nil
}

// addGitHubAuth adds GitHub-style authentication headers to the HTTP request.
// GitHub signature format: "sha256=" + HMAC-SHA256(secret, body)
func (c *AuthConfig) addGitHubAuth(req *http.Request, body []byte) error {
	if c.Secret == "" {
		return fmt.Errorf("secret is required for GitHub mode authentication")
	}

	// Calculate signature: HMAC-SHA256(secret, body)
	h := hmac.New(sha256.New, []byte(c.Secret))
	h.Write(body)
	signature := "sha256=" + hex.EncodeToString(h.Sum(nil))

	// Set single header
	signatureHeader := c.SignatureHeader
	if signatureHeader == "" {
		signatureHeader = DefaultGitHubSignatureHeader
	}
	req.Header.Set(signatureHeader, signature)

	return nil
}

// calculateHMACSignature calculates HMAC-SHA256 signature
func (c *AuthConfig) calculateHMACSignature(
	timestamp int64,
	method, path string,
	body []byte,
) string {
	// Create message: timestamp + method + path + body
	message := fmt.Sprintf("%d%s%s%s",
		timestamp,
		method,
		path,
		string(body),
	)

	// Calculate HMAC-SHA256
	h := hmac.New(sha256.New, []byte(c.Secret))
	h.Write([]byte(message))

	return hex.EncodeToString(h.Sum(nil))
}

// getFullPath returns the full request path including query parameters
func getFullPath(req *http.Request) string {
	path := req.URL.Path
	if req.URL.RawQuery != "" {
		return path + "?" + req.URL.RawQuery
	}
	return path
}

// Verify verifies the request based on the configured authentication mode.
// This is the unified verification method that automatically selects the appropriate
// verification logic based on AuthConfig.Mode.
//
// For AuthModeNone: No verification is performed, returns nil immediately.
// For AuthModeSimple: Verifies the API secret header matches the configured secret.
// For AuthModeHMAC: Verifies HMAC signature with timestamp validation and body size checks.
//
// Example:
//
//	// Create auth config
//	auth := NewAuthConfig(AuthModeSimple, "my-secret")
//
//	// Verify request in middleware
//	if err := auth.Verify(req); err != nil {
//	    http.Error(w, "Authentication failed", http.StatusUnauthorized)
//	    return
//	}
//
//	// For HMAC mode with custom options
//	auth := NewAuthConfig(AuthModeHMAC, "hmac-secret")
//	err := auth.Verify(req,
//	    WithVerifyMaxAge(10*time.Minute),
//	    WithVerifyMaxBodySize(5*1024*1024),
//	)
func (c *AuthConfig) Verify(req *http.Request, opts ...VerifyOption) error {
	if c == nil || c.Mode == AuthModeNone || c.Mode == "" {
		return nil // No authentication required
	}

	switch c.Mode {
	case AuthModeSimple:
		return c.verifySimpleAuth(req)
	case AuthModeHMAC:
		return c.verifyHMACSignature(req, opts...)
	case AuthModeGitHub:
		return c.verifyGitHubSignature(req, opts...)
	default:
		return fmt.Errorf("unsupported authentication mode: %s", c.Mode)
	}
}

// verifySimpleAuth verifies simple API secret from request (for server-side validation).
// It checks that the secret in the configured header matches the expected secret.
// This is an internal method. External users should use Verify() instead.
func (c *AuthConfig) verifySimpleAuth(req *http.Request) error {
	if c.Secret == "" {
		return fmt.Errorf("secret is required for simple authentication verification")
	}

	headerName := c.HeaderName
	if headerName == "" {
		headerName = DefaultAPISecretHeader
	}

	secret := req.Header.Get(headerName)
	if secret == "" {
		return fmt.Errorf("missing authentication header: %s", headerName)
	}

	if secret != c.Secret {
		return fmt.Errorf("authentication failed: invalid secret")
	}

	return nil
}

// verifyHMACSignature verifies HMAC signature from request (for server-side validation).
// Use WithVerifyMaxAge and WithVerifyMaxBodySize options to customize verification behavior.
// This is an internal method. External users should use Verify() instead.
func (c *AuthConfig) verifyHMACSignature(
	req *http.Request,
	opts ...VerifyOption,
) error {
	if c.Secret == "" {
		return fmt.Errorf("secret is required for HMAC verification")
	}

	// Apply options
	options := defaultVerifyOptions()
	for _, opt := range opts {
		opt(options)
	}

	// Get headers
	signatureHeader := c.SignatureHeader
	if signatureHeader == "" {
		signatureHeader = DefaultSignatureHeader
	}

	timestampHeader := c.TimestampHeader
	if timestampHeader == "" {
		timestampHeader = DefaultTimestampHeader
	}

	signature := req.Header.Get(signatureHeader)
	timestampStr := req.Header.Get(timestampHeader)

	if signature == "" || timestampStr == "" {
		return fmt.Errorf("missing authentication headers")
	}

	// Parse timestamp
	timestamp, err := strconv.ParseInt(timestampStr, 10, 64)
	if err != nil {
		return fmt.Errorf("invalid timestamp: %w", err)
	}

	requestTime := time.Unix(timestamp, 0)
	now := time.Now()
	timeDiff := now.Sub(requestTime)

	// Reject if timestamp is too old
	if timeDiff > options.MaxAge {
		return fmt.Errorf("request timestamp expired")
	}

	// Reject if timestamp is too far in the future (clock skew attack prevention)
	if timeDiff < -options.MaxAge {
		return fmt.Errorf("request timestamp is too far in the future")
	}

	// Read body with size limit to prevent DoS attacks
	limit := options.MaxBodySize
	if limit < math.MaxInt64 {
		limit++
	}
	limitedReader := io.LimitReader(req.Body, limit)
	body, err := io.ReadAll(limitedReader)
	if err != nil {
		return fmt.Errorf("failed to read body: %w", err)
	}

	// Check if body exceeded limit
	if int64(len(body)) > options.MaxBodySize {
		return fmt.Errorf("request body too large: exceeds %d bytes", options.MaxBodySize)
	}

	// Restore body for subsequent handlers
	req.Body = io.NopCloser(bytes.NewBuffer(body))

	// Calculate expected signature (including query parameters)
	expectedSignature := c.calculateHMACSignature(
		timestamp,
		req.Method,
		getFullPath(req),
		body,
	)

	// Compare signatures
	if !hmac.Equal([]byte(signature), []byte(expectedSignature)) {
		return fmt.Errorf("signature verification failed")
	}

	return nil
}

// verifyGitHubSignature verifies GitHub-style HMAC-SHA256 signatures.
//
// GitHub signature format:
// - Header: X-Hub-Signature-256 (configurable via SignatureHeader)
// - Format: "sha256=<hex_digest>"
// - Signature: HMAC-SHA256(secret, body)
//
// Note: GitHub mode does NOT include timestamp validation, as GitHub
// does not provide timestamps in webhook requests. This means the signature
// alone cannot prevent replay attacks. Use HTTPS and webhook secret rotation
// to mitigate this risk.
func (c *AuthConfig) verifyGitHubSignature(
	req *http.Request,
	opts ...VerifyOption,
) error {
	if c.Secret == "" {
		return fmt.Errorf("secret is required for GitHub mode verification")
	}

	// Apply verification options (primarily for MaxBodySize)
	options := defaultVerifyOptions()
	for _, opt := range opts {
		opt(options)
	}

	// Get signature header
	signatureHeader := c.SignatureHeader
	if signatureHeader == "" {
		signatureHeader = DefaultGitHubSignatureHeader
	}
	signature := req.Header.Get(signatureHeader)
	if signature == "" {
		return fmt.Errorf("missing %s header", signatureHeader)
	}

	// Validate signature format
	if !strings.HasPrefix(signature, "sha256=") {
		return fmt.Errorf(
			"invalid signature format: expected 'sha256=<hex>', got '%s'",
			signature,
		)
	}

	// Read body with size limit
	body, err := io.ReadAll(io.LimitReader(req.Body, options.MaxBodySize+1))
	if err != nil {
		return fmt.Errorf("failed to read request body: %w", err)
	}

	// Check body size
	if int64(len(body)) > options.MaxBodySize {
		return fmt.Errorf(
			"request body too large: %d bytes exceeds limit of %d bytes",
			len(body),
			options.MaxBodySize,
		)
	}

	// Restore body for subsequent handlers
	req.Body = io.NopCloser(bytes.NewBuffer(body))

	// Calculate expected signature
	h := hmac.New(sha256.New, []byte(c.Secret))
	h.Write(body)
	expectedSignature := "sha256=" + hex.EncodeToString(h.Sum(nil))

	// Constant-time comparison to prevent timing attacks
	if !hmac.Equal([]byte(signature), []byte(expectedSignature)) {
		return fmt.Errorf("signature verification failed")
	}

	return nil
}
