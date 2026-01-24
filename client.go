package httpclient

import (
	"bytes"
	"context"
	"crypto/tls"
	"crypto/x509"
	"fmt"
	"io"
	"net/http"
	"os"
	"time"
)

// ClientOption is a function type for configuring the HTTP client.
type ClientOption func(*clientOptions)

// clientOptions holds all optional client configuration.
type clientOptions struct {
	// Authentication-related options
	headerName      string // Header name for simple mode
	signatureHeader string // Signature header for HMAC mode
	timestampHeader string // Timestamp header for HMAC mode
	nonceHeader     string // Nonce header for HMAC mode

	// Client behavior options
	transport    http.RoundTripper
	timeout      time.Duration
	maxBodySize  int64
	skipAuthFunc func(*http.Request) bool

	// TLS certificate options
	tlsCerts [][]byte // Custom TLS certificates in PEM format
}

// defaultClientOptions returns a clientOptions struct with sensible defaults.
func defaultClientOptions() *clientOptions {
	return &clientOptions{
		// Authentication defaults (consistent with NewAuthConfig)
		headerName:      "X-API-Secret",
		signatureHeader: "X-Signature",
		timestampHeader: "X-Timestamp",
		nonceHeader:     "X-Nonce",

		// Client behavior defaults
		transport:    nil, // Will use http.DefaultTransport if not specified
		timeout:      30 * time.Second,
		maxBodySize:  10 * 1024 * 1024, // 10MB
		skipAuthFunc: nil,
	}
}

// WithHeaderName sets a custom header name for simple authentication mode.
//
// Default: "X-API-Secret"
//
// Example:
//
//	client := NewAuthClient(AuthModeSimple, "key",
//	    WithHeaderName("Authorization"))
func WithHeaderName(name string) ClientOption {
	return func(opts *clientOptions) {
		opts.headerName = name
	}
}

// WithHMACHeaders sets custom header names for HMAC authentication mode.
//
// Default: signature="X-Signature", timestamp="X-Timestamp", nonce="X-Nonce"
//
// Example:
//
//	client := NewAuthClient(AuthModeHMAC, "secret",
//	    WithHMACHeaders("X-Sig", "X-Time", "X-ID"))
func WithHMACHeaders(signature, timestamp, nonce string) ClientOption {
	return func(opts *clientOptions) {
		opts.signatureHeader = signature
		opts.timestampHeader = timestamp
		opts.nonceHeader = nonce
	}
}

// WithTransport sets a custom underlying HTTP transport.
//
// Default: http.DefaultTransport
//
// Example:
//
//	customTransport := &http.Transport{
//	    MaxIdleConns: 100,
//	}
//	client := NewAuthClient(AuthModeHMAC, "secret",
//	    WithTransport(customTransport))
func WithTransport(transport http.RoundTripper) ClientOption {
	return func(opts *clientOptions) {
		opts.transport = transport
	}
}

// WithTimeout sets the request timeout for the HTTP client.
//
// Default: 30 seconds
//
// Example:
//
//	client := NewAuthClient(AuthModeHMAC, "secret",
//	    WithTimeout(10*time.Second))
func WithTimeout(timeout time.Duration) ClientOption {
	return func(opts *clientOptions) {
		opts.timeout = timeout
	}
}

// WithMaxBodySize sets the maximum request body size in bytes.
// Requests with larger bodies will return an error.
// Set to 0 to disable the limit (not recommended).
//
// Default: 10MB (10 * 1024 * 1024 bytes)
//
// Example:
//
//	client := NewAuthClient(AuthModeHMAC, "secret",
//	    WithMaxBodySize(5*1024*1024)) // 5MB limit
func WithMaxBodySize(maxBytes int64) ClientOption {
	return func(opts *clientOptions) {
		opts.maxBodySize = maxBytes
	}
}

// WithSkipAuthFunc sets a function that determines whether to skip authentication
// for a given request. This is useful for health checks or other public endpoints.
//
// Example:
//
//	client := NewAuthClient(AuthModeHMAC, "secret",
//	    WithSkipAuthFunc(func(req *http.Request) bool {
//	        return strings.HasPrefix(req.URL.Path, "/health")
//	    }))
func WithSkipAuthFunc(fn func(*http.Request) bool) ClientOption {
	return func(opts *clientOptions) {
		opts.skipAuthFunc = fn
	}
}

// WithTLSCertFromURL downloads a TLS certificate from the specified URL and adds it
// to the trusted certificate pool. This is useful for enterprise environments with
// custom certificate authorities.
//
// The certificate must be in PEM format. Multiple certificates can be added by
// calling this function multiple times.
//
// Example:
//
//	client := NewAuthClient(AuthModeHMAC, "secret",
//	    WithTLSCertFromURL("https://internal-ca.company.com/ca.crt"))
func WithTLSCertFromURL(url string) ClientOption {
	return func(opts *clientOptions) {
		// Download certificate from URL using a simple HTTP client
		// Create request with context
		req, err := http.NewRequestWithContext(
			context.Background(),
			http.MethodGet,
			url,
			nil,
		)
		if err != nil {
			return
		}

		// #nosec G107 - URL is provided by the user, not external input
		resp, err := http.DefaultClient.Do(req)
		if err != nil {
			// Store error for later handling in NewAuthClient
			return
		}
		defer resp.Body.Close()

		if resp.StatusCode != http.StatusOK {
			return
		}

		certPEM, err := io.ReadAll(resp.Body)
		if err != nil {
			return
		}

		opts.tlsCerts = append(opts.tlsCerts, certPEM)
	}
}

// WithTLSCertFromFile reads a TLS certificate from the specified file path and adds it
// to the trusted certificate pool. This is useful for enterprise environments with
// custom certificate authorities.
//
// The certificate must be in PEM format. Multiple certificates can be added by
// calling this function multiple times.
//
// Example:
//
//	client := NewAuthClient(AuthModeHMAC, "secret",
//	    WithTLSCertFromFile("/etc/ssl/certs/company-ca.crt"))
func WithTLSCertFromFile(path string) ClientOption {
	return func(opts *clientOptions) {
		certPEM, err := os.ReadFile(path)
		if err != nil {
			// Store error for later handling in NewAuthClient
			return
		}
		opts.tlsCerts = append(opts.tlsCerts, certPEM)
	}
}

// WithTLSCertFromBytes adds a TLS certificate from byte content to the trusted
// certificate pool. This is useful for embedding certificates directly in the
// application or loading them from external sources.
//
// The certificate must be in PEM format. Multiple certificates can be added by
// calling this function multiple times.
//
// Example:
//
//	certPEM := []byte(`-----BEGIN CERTIFICATE-----
//	MIIDXTCCAkWgAwIBAgIJAKL0UG+mRKm...
//	-----END CERTIFICATE-----`)
//	client := NewAuthClient(AuthModeHMAC, "secret",
//	    WithTLSCertFromBytes(certPEM))
func WithTLSCertFromBytes(certPEM []byte) ClientOption {
	return func(opts *clientOptions) {
		opts.tlsCerts = append(opts.tlsCerts, certPEM)
	}
}

// authRoundTripper implements http.RoundTripper with automatic authentication.
type authRoundTripper struct {
	config       *AuthConfig
	transport    http.RoundTripper
	maxBodySize  int64
	skipAuthFunc func(*http.Request) bool
}

// RoundTrip executes a single HTTP transaction with automatic authentication.
// It reads the request body, adds authentication headers, restores the body,
// and forwards the request to the underlying transport.
func (t *authRoundTripper) RoundTrip(req *http.Request) (*http.Response, error) {
	// Check if authentication should be skipped for this request
	if t.skipAuthFunc != nil && t.skipAuthFunc(req) {
		// Skip authentication, use underlying transport directly
		transport := t.transport
		if transport == nil {
			transport = http.DefaultTransport
		}
		return transport.RoundTrip(req)
	}

	// Handle nil or empty body (GET, DELETE, etc.)
	var bodyBytes []byte
	if req.Body != nil && req.Body != http.NoBody {
		// Check body size limit to prevent OOM
		if t.maxBodySize > 0 {
			// Read with size limit
			limitedReader := io.LimitReader(req.Body, t.maxBodySize+1)
			var err error
			bodyBytes, err = io.ReadAll(limitedReader)
			if err != nil {
				return nil, fmt.Errorf("failed to read request body: %w", err)
			}
			// Check if body exceeds limit
			if int64(len(bodyBytes)) > t.maxBodySize {
				return nil, fmt.Errorf(
					"request body exceeds maximum size of %d bytes",
					t.maxBodySize,
				)
			}
		} else {
			// No size limit
			var err error
			bodyBytes, err = io.ReadAll(req.Body)
			if err != nil {
				return nil, fmt.Errorf("failed to read request body: %w", err)
			}
		}

		// Close original body
		_ = req.Body.Close()

		// Restore body for downstream transport
		req.Body = io.NopCloser(bytes.NewReader(bodyBytes))
	}

	// Add authentication headers using existing logic
	if err := t.config.AddAuthHeaders(req, bodyBytes); err != nil {
		return nil, fmt.Errorf("failed to add auth headers: %w", err)
	}

	// Use underlying transport (default to http.DefaultTransport)
	transport := t.transport
	if transport == nil {
		transport = http.DefaultTransport
	}

	return transport.RoundTrip(req)
}

// NewAuthClient creates an HTTP client with automatic authentication.
//
// The client automatically adds authentication headers to all requests
// based on the specified mode (none, simple, or HMAC).
//
// Parameters:
//   - mode: Authentication mode (AuthModeNone, AuthModeSimple, AuthModeHMAC)
//   - secret: Shared secret key for authentication
//   - opts: Optional configuration (timeout, custom headers, etc.)
//
// Example (minimal):
//
//	client := httpclient.NewAuthClient(httpclient.AuthModeHMAC, "secret")
//	resp, err := client.Get("https://api.example.com/data")
//
// Example (with options):
//
//	client := httpclient.NewAuthClient(
//	    httpclient.AuthModeHMAC,
//	    "secret",
//	    httpclient.WithTimeout(10*time.Second),
//	    httpclient.WithMaxBodySize(5*1024*1024),
//	    httpclient.WithSkipAuthFunc(func(req *http.Request) bool {
//	        return strings.HasPrefix(req.URL.Path, "/health")
//	    }),
//	)
//
// Example (with custom TLS certificate):
//
//	client := httpclient.NewAuthClient(
//	    httpclient.AuthModeHMAC,
//	    "secret",
//	    httpclient.WithTLSCertFromFile("/etc/ssl/certs/company-ca.crt"),
//	)
//
// Note: This implementation reads the entire request body into memory
// for signature calculation. For large file uploads (>10MB), consider
// using AddAuthHeaders directly with streaming.
func NewAuthClient(mode, secret string, opts ...ClientOption) *http.Client {
	// Apply default configuration
	options := defaultClientOptions()

	// Apply user-provided options
	for _, opt := range opts {
		opt(options)
	}

	// Configure TLS if custom certificates are provided
	transport := options.transport
	if len(options.tlsCerts) > 0 {
		transport = buildTLSTransport(options.transport, options.tlsCerts)
	}

	// Create AuthConfig (internal use)
	config := &AuthConfig{
		Mode:            mode,
		Secret:          secret,
		HeaderName:      options.headerName,
		SignatureHeader: options.signatureHeader,
		TimestampHeader: options.timestampHeader,
		NonceHeader:     options.nonceHeader,
	}

	// Create authRoundTripper
	authTransport := &authRoundTripper{
		config:       config,
		transport:    transport,
		maxBodySize:  options.maxBodySize,
		skipAuthFunc: options.skipAuthFunc,
	}

	// Create and return http.Client
	return &http.Client{
		Transport: authTransport,
		Timeout:   options.timeout,
	}
}

// buildTLSTransport creates or modifies an HTTP transport with custom TLS certificates.
func buildTLSTransport(baseTransport http.RoundTripper, certs [][]byte) http.RoundTripper {
	// Start with system cert pool
	certPool, err := x509.SystemCertPool()
	if err != nil {
		// If system pool is unavailable, create a new empty pool
		certPool = x509.NewCertPool()
	}

	// Add custom certificates to the pool
	for _, certPEM := range certs {
		// Skip invalid certificates silently
		certPool.AppendCertsFromPEM(certPEM)
	}

	// Create TLS config with custom cert pool
	tlsConfig := &tls.Config{
		RootCAs:    certPool,
		MinVersion: tls.VersionTLS12, // Enforce TLS 1.2 minimum for security
	}

	// If a base transport is provided, try to clone and modify it
	if baseTransport != nil {
		if httpTransport, ok := baseTransport.(*http.Transport); ok {
			// Clone the transport to avoid modifying the original
			transport := httpTransport.Clone()
			transport.TLSClientConfig = tlsConfig
			return transport
		}
		// If it's not an *http.Transport, we can't modify it safely
		// Return the base transport as-is (user's responsibility)
		return baseTransport
	}

	// No base transport provided, create a new one based on http.DefaultTransport
	defaultTransport := http.DefaultTransport.(*http.Transport)
	transport := defaultTransport.Clone()
	transport.TLSClientConfig = tlsConfig

	return transport
}
