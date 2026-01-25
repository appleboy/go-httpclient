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
	"time"

	"github.com/google/uuid"
)

// Authentication mode constants
const (
	AuthModeNone   = "none"   // No authentication
	AuthModeSimple = "simple" // Simple API secret in header
	AuthModeHMAC   = "hmac"   // HMAC-SHA256 signature
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
		MaxAge:      5 * time.Minute,
		MaxBodySize: 10 * 1024 * 1024, // 10MB
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
	return &AuthConfig{
		Mode:            mode,
		Secret:          secret,
		HeaderName:      "X-API-Secret",
		SignatureHeader: "X-Signature",
		TimestampHeader: "X-Timestamp",
		NonceHeader:     "X-Nonce",
	}
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
		headerName = "X-API-Secret"
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
		signatureHeader = "X-Signature"
	}

	timestampHeader := c.TimestampHeader
	if timestampHeader == "" {
		timestampHeader = "X-Timestamp"
	}

	nonceHeader := c.NonceHeader
	if nonceHeader == "" {
		nonceHeader = "X-Nonce"
	}

	req.Header.Set(signatureHeader, signature)
	req.Header.Set(timestampHeader, strconv.FormatInt(timestamp, 10))
	req.Header.Set(nonceHeader, nonce)

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

// VerifyHMACSignature verifies HMAC signature from request (for server-side validation)
// Use WithVerifyMaxAge and WithVerifyMaxBodySize options to customize verification behavior.
//
// Example:
//
//	// Use defaults (5 minutes, 10MB)
//	err := auth.VerifyHMACSignature(req)
//
//	// Custom max age
//	err := auth.VerifyHMACSignature(req, WithVerifyMaxAge(10*time.Minute))
//
//	// Custom body size limit
//	err := auth.VerifyHMACSignature(req, WithVerifyMaxBodySize(5*1024*1024))
//
//	// Multiple options
//	err := auth.VerifyHMACSignature(req,
//	    WithVerifyMaxAge(10*time.Minute),
//	    WithVerifyMaxBodySize(5*1024*1024),
//	)
func (c *AuthConfig) VerifyHMACSignature(
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
		signatureHeader = "X-Signature"
	}

	timestampHeader := c.TimestampHeader
	if timestampHeader == "" {
		timestampHeader = "X-Timestamp"
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
