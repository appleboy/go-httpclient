package httpclient

import (
	"bytes"
	"crypto/tls"
	"crypto/x509"
	"errors"
	"fmt"
	"io"
	"net/http"
)

const (
	// maxCertSize defines the maximum allowed size for a TLS certificate file.
	// This prevents memory exhaustion attacks when downloading certificates from URLs.
	// A typical certificate is 1-2KB; 1MB provides ample room for certificate chains.
	maxCertSize = 1 * 1024 * 1024 // 1MB
)

// authRoundTripper implements http.RoundTripper with automatic authentication.
type authRoundTripper struct {
	config          *AuthConfig
	transport       http.RoundTripper
	maxBodySize     int64
	skipAuthFunc    func(*http.Request) bool
	requestIDFunc   func() string
	requestIDHeader string
}

// RoundTrip executes a single HTTP transaction with automatic authentication.
// It reads the request body, adds authentication headers, restores the body,
// and forwards the request to the underlying transport.
func (t *authRoundTripper) RoundTrip(req *http.Request) (*http.Response, error) {
	// Add request ID header if configured (before skip check to track all requests)
	if t.requestIDFunc != nil {
		headerName := t.requestIDHeader
		if headerName == "" {
			headerName = DefaultRequestIDHeader
		}
		// Only add if not already present (preserve user-provided IDs)
		if req.Header.Get(headerName) == "" {
			req.Header.Set(headerName, t.requestIDFunc())
		}
	}

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
	if err := t.config.addAuthHeaders(req, bodyBytes); err != nil {
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
// Returns an error if any option fails (e.g., certificate file not found,
// invalid mTLS certificate pair, or failed to download certificate from URL).
//
// Example (minimal):
//
//	client, err := httpclient.NewAuthClient(httpclient.AuthModeHMAC, "secret")
//	if err != nil {
//	    log.Fatal(err)
//	}
//	resp, err := client.Get("https://api.example.com/data")
//
// Example (with options):
//
//	client, err := httpclient.NewAuthClient(
//	    httpclient.AuthModeHMAC,
//	    "secret",
//	    httpclient.WithTimeout(10*time.Second),
//	    httpclient.WithMaxBodySize(5*1024*1024),
//	    httpclient.WithSkipAuthFunc(func(req *http.Request) bool {
//	        return strings.HasPrefix(req.URL.Path, "/health")
//	    }),
//	)
//	if err != nil {
//	    log.Fatal(err)
//	}
//
// Example (with custom TLS certificate):
//
//	ctx := context.Background()
//	client, err := httpclient.NewAuthClient(
//	    httpclient.AuthModeHMAC,
//	    "secret",
//	    httpclient.WithTLSCertFromFile("/etc/ssl/certs/company-ca.crt"),
//	    httpclient.WithTLSCertFromURL(ctx, "https://ca.example.com/cert.pem"),
//	)
//	if err != nil {
//	    log.Fatal(err)
//	}
//
// Example (skip TLS verification for testing):
//
//	client, err := httpclient.NewAuthClient(
//	    httpclient.AuthModeHMAC,
//	    "secret",
//	    httpclient.WithInsecureSkipVerify(true),
//	)
//	if err != nil {
//	    log.Fatal(err)
//	}
//
// Example (with mTLS):
//
//	client, err := httpclient.NewAuthClient(
//	    httpclient.AuthModeHMAC,
//	    "secret",
//	    httpclient.WithMTLSFromFile("/path/to/client.crt", "/path/to/client.key"),
//	)
//	if err != nil {
//	    log.Fatal(err)
//	}
//
// Note: This implementation reads the entire request body into memory
// for signature calculation. For large file uploads (>10MB), consider
// using AddAuthHeaders directly with streaming.
func NewAuthClient(mode, secret string, opts ...ClientOption) (*http.Client, error) {
	// Apply default configuration
	options := defaultClientOptions()

	// Apply user-provided options
	for _, opt := range opts {
		opt(options)
	}

	// Check for errors from options - return all accumulated errors
	if len(options.errors) > 0 {
		return nil, errors.Join(options.errors...)
	}

	// Detect conflicts between TLS options and non-Transport RoundTrippers
	if options.hasTLSOptions() && options.isNonTransportRoundTripper() {
		return nil, fmt.Errorf(
			"TLS options (WithTLSCert*, WithMTLS*, WithInsecureSkipVerify) cannot be combined " +
				"with non-Transport RoundTrippers provided via WithTransport(). " +
				"Please configure TLS settings in your custom *http.Transport instead. " +
				"Example:\n" +
				"    transport := &http.Transport{\n" +
				"        TLSClientConfig: &tls.Config{\n" +
				"            RootCAs: yourCertPool,\n" +
				"        },\n" +
				"    }\n" +
				"    client := NewAuthClient(mode, secret, WithTransport(transport))",
		)
	}

	// Configure TLS if custom certificates, mTLS, or insecureSkipVerify are provided
	transport := options.transport
	if len(options.tlsCerts) > 0 ||
		(len(options.clientCertPEM) > 0 && len(options.clientKeyPEM) > 0) ||
		options.insecureSkipVerify {
		transport = buildTLSTransport(
			options.transport,
			options.tlsCerts,
			options.clientCertPEM,
			options.clientKeyPEM,
			options.insecureSkipVerify,
		)
	}

	// Create AuthConfig (internal use)
	config := &AuthConfig{
		Mode:            mode,
		Secret:          NewSecureString(secret),
		HeaderName:      options.headerName,
		SignatureHeader: options.signatureHeader,
		TimestampHeader: options.timestampHeader,
		NonceHeader:     options.nonceHeader,
	}

	// GitHub mode uses different default header
	if mode == AuthModeGitHub &&
		(options.signatureHeader == "" || options.signatureHeader == DefaultSignatureHeader) {
		config.SignatureHeader = DefaultGitHubSignatureHeader
	}

	// Create authRoundTripper
	authTransport := &authRoundTripper{
		config:          config,
		transport:       transport,
		maxBodySize:     options.maxBodySize,
		skipAuthFunc:    options.skipAuthFunc,
		requestIDFunc:   options.requestIDFunc,
		requestIDHeader: options.requestIDHeader,
	}

	// Create and return http.Client
	return &http.Client{
		Transport: authTransport,
		Timeout:   options.timeout,
	}, nil
}

// buildTLSTransport creates or modifies an HTTP transport with custom TLS certificates,
// optional mTLS client certificates, and/or insecure skip verify.
//
// This function expects baseTransport to be either nil or an *http.Transport.
// Non-Transport RoundTrippers should be rejected earlier via conflict detection.
func buildTLSTransport(
	baseTransport http.RoundTripper,
	certs [][]byte,
	clientCertPEM, clientKeyPEM []byte,
	insecureSkipVerify bool,
) http.RoundTripper {
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

	// Prepare mTLS client certificates if provided
	var clientCerts []tls.Certificate
	if len(clientCertPEM) > 0 && len(clientKeyPEM) > 0 {
		cert, err := tls.X509KeyPair(clientCertPEM, clientKeyPEM)
		if err != nil {
			// This should not happen as we validate in the option function
			// But handle it defensively by skipping the client cert
		} else {
			clientCerts = append(clientCerts, cert)
		}
	}

	// Create TLS config with custom cert pool, client certificates, and insecure skip verify
	tlsConfig := &tls.Config{
		RootCAs:      certPool,
		Certificates: clientCerts,
		MinVersion:   tls.VersionTLS12, // Enforce TLS 1.2 minimum for security
		// #nosec G402 - InsecureSkipVerify is intentionally configurable via WithInsecureSkipVerify()
		// for testing/development environments. Production usage warning is documented in the function.
		InsecureSkipVerify: insecureSkipVerify,
	}

	// If a base transport is provided, clone and modify it
	if baseTransport != nil {
		if httpTransport, ok := baseTransport.(*http.Transport); ok {
			// Clone the transport to avoid modifying the original
			transport := httpTransport.Clone()
			transport.TLSClientConfig = tlsConfig
			return transport
		}
		// This should never happen due to conflict detection in NewAuthClient,
		// but handle it defensively by creating a new transport
	}

	// No base transport provided (or non-Transport which shouldn't happen),
	// create a new one based on http.DefaultTransport
	defaultTransport := http.DefaultTransport.(*http.Transport)
	transport := defaultTransport.Clone()
	transport.TLSClientConfig = tlsConfig

	return transport
}
