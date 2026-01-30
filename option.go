package httpclient

import (
	"context"
	"crypto/tls"
	"crypto/x509"
	"fmt"
	"io"
	"net/http"
	"os"
	"time"
)

// Default client option constants
const (
	DefaultClientTimeout    = 30 * time.Second // Default HTTP client timeout
	DefaultCertFetchTimeout = 30 * time.Second // Default timeout for fetching certificates from URLs
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

	// Request tracking options
	requestIDFunc   func() string // Function to generate request IDs
	requestIDHeader string        // Header name for request ID

	// TLS certificate options
	tlsCerts           [][]byte // Custom TLS certificates in PEM format
	minTLSVersion      uint16   // Minimum TLS version (default: TLS 1.2)
	insecureSkipVerify bool     // Skip TLS certificate verification

	// mTLS client certificate options
	clientCertPEM []byte // Client certificate in PEM format
	clientKeyPEM  []byte // Client private key in PEM format

	// Error tracking
	errors []error // Errors collected from options
}

// hasTLSOptions returns true if any TLS-related options are configured.
func (o *clientOptions) hasTLSOptions() bool {
	return len(o.tlsCerts) > 0 ||
		(len(o.clientCertPEM) > 0 && len(o.clientKeyPEM) > 0) ||
		o.minTLSVersion != 0 ||
		o.insecureSkipVerify
}

// isNonTransportRoundTripper returns true if the configured transport is not nil
// and not an *http.Transport.
func (o *clientOptions) isNonTransportRoundTripper() bool {
	if o.transport == nil {
		return false
	}
	_, ok := o.transport.(*http.Transport)
	return !ok
}

// defaultClientOptions returns a clientOptions struct with sensible defaults.
func defaultClientOptions() *clientOptions {
	return &clientOptions{
		// Authentication defaults (consistent with NewAuthConfig)
		headerName:      DefaultAPISecretHeader,
		signatureHeader: DefaultSignatureHeader,
		timestampHeader: DefaultTimestampHeader,
		nonceHeader:     DefaultNonceHeader,

		// Client behavior defaults
		transport:    nil, // Will use http.DefaultTransport if not specified
		timeout:      DefaultClientTimeout,
		maxBodySize:  DefaultVerifyMaxBodySize,
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
// IMPORTANT: If you use TLS options (WithTLSCert*, WithMTLS*, WithInsecureSkipVerify),
// you must provide an *http.Transport (not any other RoundTripper implementation).
// Non-Transport RoundTrippers cannot be combined with TLS options and will return an error.
//
// If you need custom middleware (logging, metrics, tracing) with TLS options,
// configure TLS in your *http.Transport and wrap it with your middleware after
// creating the client:
//
//	// 1. Create Transport with TLS
//	transport := &http.Transport{
//	    TLSClientConfig: &tls.Config{
//	        RootCAs: certPool,
//	    },
//	}
//
//	// 2. Create authenticated client
//	authClient, _ := NewAuthClient(AuthModeHMAC, secret, WithTransport(transport))
//
//	// 3. Wrap with your middleware
//	authClient.Transport = &LoggingRoundTripper{
//	    Next: authClient.Transport,
//	}
//
// Example (basic):
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

// WithRequestID sets a function that generates unique request IDs for request tracing.
// The generated ID will be automatically added to each request in the X-Request-ID header
// (or custom header name set via WithRequestIDHeader).
//
// This is useful for:
// - Correlating client-side and server-side logs
// - Distributed tracing across microservices
// - Debugging and troubleshooting request flows
//
// Default: No request ID is added
//
// Example with UUID:
//
//	import "github.com/google/uuid"
//	client := NewAuthClient(AuthModeHMAC, "secret",
//	    WithRequestID(func() string {
//	        return uuid.New().String()
//	    }))
//
// Example with custom format:
//
//	client := NewAuthClient(AuthModeHMAC, "secret",
//	    WithRequestID(func() string {
//	        return fmt.Sprintf("req-%d-%s", time.Now().Unix(), randomString(8))
//	    }))
func WithRequestID(fn func() string) ClientOption {
	return func(opts *clientOptions) {
		opts.requestIDFunc = fn
	}
}

// WithRequestIDHeader sets a custom header name for the request ID.
// This is only used when WithRequestID is also configured.
//
// Default: "X-Request-ID"
//
// Example:
//
//	client := NewAuthClient(AuthModeHMAC, "secret",
//	    WithRequestID(uuid.New().String),
//	    WithRequestIDHeader("X-Correlation-ID"))
func WithRequestIDHeader(name string) ClientOption {
	return func(opts *clientOptions) {
		opts.requestIDHeader = name
	}
}

// WithInsecureSkipVerify disables TLS certificate verification.
// This is useful for testing with self-signed certificates or development environments.
//
// WARNING: This makes your application vulnerable to man-in-the-middle attacks.
// Never use this in production environments.
//
// Example:
//
//	client := NewAuthClient(AuthModeHMAC, "secret",
//	    WithInsecureSkipVerify(true))
func WithInsecureSkipVerify(skip bool) ClientOption {
	return func(opts *clientOptions) {
		opts.insecureSkipVerify = skip
	}
}

// WithMinTLSVersion sets the minimum TLS version for HTTPS connections.
// By default, TLS 1.2 is used for backwards compatibility with older servers.
//
// Common values:
//   - tls.VersionTLS12 (0x0303) - TLS 1.2 (default, widely supported)
//   - tls.VersionTLS13 (0x0304) - TLS 1.3 (enhanced security, faster handshakes)
//
// Note: TLS 1.3 provides stronger security with improved cipher suites, forward secrecy,
// and faster handshakes, but may not be supported by older servers. Use TLS 1.3 when
// you control both client and server, or when security requirements mandate it.
//
// Example (enforce TLS 1.3):
//
//	client, err := httpclient.NewAuthClient(
//	    httpclient.AuthModeHMAC,
//	    "secret",
//	    httpclient.WithMinTLSVersion(tls.VersionTLS13),
//	)
func WithMinTLSVersion(version uint16) ClientOption {
	return func(opts *clientOptions) {
		opts.minTLSVersion = version
	}
}

// WithTLSCertFromURL downloads a TLS certificate from the specified URL and adds it
// to the trusted certificate pool. This is useful for enterprise environments with
// custom certificate authorities.
//
// The certificate must be in PEM format. Multiple certificates can be added by
// calling this function multiple times.
//
// Security: The download uses system certificate pool for TLS verification to prevent
// MITM attacks during certificate retrieval. The connection enforces TLS 1.2+ security.
//
// Example:
//
//	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
//	defer cancel()
//	client := NewAuthClient(AuthModeHMAC, "secret",
//	    WithTLSCertFromURL(ctx, "https://internal-ca.company.com/ca.crt"))
func WithTLSCertFromURL(ctx context.Context, url string) ClientOption {
	return func(opts *clientOptions) {
		// Create a secure HTTP client using system certificate pool
		// to verify the certificate server's identity (prevents MITM)
		systemCerts, err := x509.SystemCertPool()
		if err != nil || systemCerts == nil {
			// Fallback to empty pool if system pool is unavailable
			systemCerts = x509.NewCertPool()
		}

		tlsConfig := &tls.Config{
			RootCAs:    systemCerts,
			MinVersion: defaultTLSMinVersion,
		}

		secureClient := &http.Client{
			Transport: &http.Transport{
				TLSClientConfig: tlsConfig,
			},
			Timeout: DefaultCertFetchTimeout,
		}

		// Create request with provided context
		req, err := http.NewRequestWithContext(
			ctx,
			http.MethodGet,
			url,
			nil,
		)
		if err != nil {
			opts.errors = append(
				opts.errors,
				fmt.Errorf("failed to create request for TLS cert from %s: %w", url, err),
			)
			return
		}

		// #nosec G107 - URL is provided by the user, not external input
		resp, err := secureClient.Do(req)
		if err != nil {
			opts.errors = append(
				opts.errors,
				fmt.Errorf("failed to download TLS cert from %s: %w", url, err),
			)
			return
		}
		defer resp.Body.Close()

		if resp.StatusCode != http.StatusOK {
			opts.errors = append(
				opts.errors,
				fmt.Errorf("failed to download TLS cert from %s: HTTP %d", url, resp.StatusCode),
			)
			return
		}

		// Use LimitReader to prevent memory exhaustion from malicious servers
		// that might send extremely large responses
		limitedReader := io.LimitReader(resp.Body, maxCertSize+1)
		certPEM, err := io.ReadAll(limitedReader)
		if err != nil {
			opts.errors = append(
				opts.errors,
				fmt.Errorf("failed to read TLS cert from %s: %w", url, err),
			)
			return
		}

		// Check if the certificate exceeds the maximum allowed size
		if int64(len(certPEM)) > maxCertSize {
			opts.errors = append(
				opts.errors,
				fmt.Errorf(
					"certificate from %s exceeds maximum size of %d bytes (got %d bytes)",
					url,
					maxCertSize,
					len(certPEM),
				),
			)
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
			opts.errors = append(
				opts.errors,
				fmt.Errorf("failed to read TLS cert from %s: %w", path, err),
			)
			return
		}

		// Check if the certificate file exceeds the maximum allowed size
		if int64(len(certPEM)) > maxCertSize {
			opts.errors = append(
				opts.errors,
				fmt.Errorf(
					"certificate file %s exceeds maximum size of %d bytes (got %d bytes)",
					path,
					maxCertSize,
					len(certPEM),
				),
			)
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
		// Check if the certificate exceeds the maximum allowed size
		if int64(len(certPEM)) > maxCertSize {
			opts.errors = append(
				opts.errors,
				fmt.Errorf(
					"certificate exceeds maximum size of %d bytes (got %d bytes)",
					maxCertSize,
					len(certPEM),
				),
			)
			return
		}

		opts.tlsCerts = append(opts.tlsCerts, certPEM)
	}
}

// WithMTLSFromFile loads a client certificate and private key from files for mTLS
// (mutual TLS) authentication. The certificate and key must be in PEM format.
//
// mTLS provides two-way authentication where both the client and server verify
// each other's identity using certificates.
//
// Example:
//
//	client, err := NewAuthClient(AuthModeHMAC, "secret",
//	    WithMTLSFromFile("/path/to/client.crt", "/path/to/client.key"))
//	if err != nil {
//	    log.Fatal(err)
//	}
func WithMTLSFromFile(certPath, keyPath string) ClientOption {
	return func(opts *clientOptions) {
		certPEM, err := os.ReadFile(certPath)
		if err != nil {
			opts.errors = append(
				opts.errors,
				fmt.Errorf("failed to read mTLS cert from %s: %w", certPath, err),
			)
			return
		}

		keyPEM, err := os.ReadFile(keyPath)
		if err != nil {
			opts.errors = append(
				opts.errors,
				fmt.Errorf("failed to read mTLS key from %s: %w", keyPath, err),
			)
			return
		}

		// Validate that the cert and key pair is valid
		_, err = tls.X509KeyPair(certPEM, keyPEM)
		if err != nil {
			opts.errors = append(
				opts.errors,
				fmt.Errorf(
					"invalid mTLS cert/key pair from files %s and %s: %w",
					certPath,
					keyPath,
					err,
				),
			)
			return
		}

		opts.clientCertPEM = certPEM
		opts.clientKeyPEM = keyPEM
	}
}

// WithMTLSFromBytes loads a client certificate and private key from byte content
// for mTLS (mutual TLS) authentication. The certificate and key must be in PEM format.
//
// mTLS provides two-way authentication where both the client and server verify
// each other's identity using certificates.
//
// Example:
//
//	certPEM := []byte(`-----BEGIN CERTIFICATE-----...-----END CERTIFICATE-----`)
//	keyPEM := []byte(`-----BEGIN PRIVATE KEY-----...-----END PRIVATE KEY-----`)
//	client, err := NewAuthClient(AuthModeHMAC, "secret",
//	    WithMTLSFromBytes(certPEM, keyPEM))
//	if err != nil {
//	    log.Fatal(err)
//	}
func WithMTLSFromBytes(certPEM, keyPEM []byte) ClientOption {
	return func(opts *clientOptions) {
		// Validate that the cert and key pair is valid
		_, err := tls.X509KeyPair(certPEM, keyPEM)
		if err != nil {
			opts.errors = append(opts.errors, fmt.Errorf("invalid mTLS cert/key pair: %w", err))
			return
		}

		opts.clientCertPEM = certPEM
		opts.clientKeyPEM = keyPEM
	}
}
