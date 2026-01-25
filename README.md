# go-httpclient

[![Trivy Security Scan](https://github.com/appleboy/go-httpclient/actions/workflows/security.yml/badge.svg)](https://github.com/appleboy/go-httpclient/actions/workflows/security.yml)
[![Testing](https://github.com/appleboy/go-httpclient/actions/workflows/testing.yml/badge.svg)](https://github.com/appleboy/go-httpclient/actions/workflows/testing.yml)
[![CodeQL](https://github.com/appleboy/go-httpclient/actions/workflows/codeql.yml/badge.svg)](https://github.com/appleboy/go-httpclient/actions/workflows/codeql.yml)
[![codecov](https://codecov.io/gh/appleboy/go-httpclient/branch/main/graph/badge.svg)](https://codecov.io/gh/appleboy/go-httpclient)
[![Go Report Card](https://goreportcard.com/badge/github.com/appleboy/go-httpclient)](https://goreportcard.com/report/github.com/appleboy/go-httpclient)
[![Go Reference](https://pkg.go.dev/badge/github.com/appleboy/go-httpclient.svg)](https://pkg.go.dev/github.com/appleboy/go-httpclient)
[![License: MIT](https://img.shields.io/badge/License-MIT-blue.svg)](https://opensource.org/licenses/MIT)

A lightweight, flexible Go package for adding configurable authentication to HTTP requests. Supports multiple authentication strategies including HMAC-SHA256 signatures with built-in protection against replay attacks and query parameter tampering.

## Table of Contents

- [go-httpclient](#go-httpclient)
  - [Table of Contents](#table-of-contents)
  - [Why](#why)
  - [What](#what)
    - [Three Authentication Modes](#three-authentication-modes)
    - [Key Benefits](#key-benefits)
  - [How](#how)
    - [Installation](#installation)
    - [Quick Start](#quick-start)
    - [Usage Examples](#usage-examples)
      - [No Authentication](#no-authentication)
      - [Simple API Key Authentication](#simple-api-key-authentication)
      - [HMAC Signature Authentication](#hmac-signature-authentication)
      - [Custom Header Names](#custom-header-names)
      - [Server-Side Verification](#server-side-verification)
      - [Automatic Authentication with RoundTripper](#automatic-authentication-with-roundtripper)
      - [Custom TLS Certificates](#custom-tls-certificates)
  - [Features](#features)
  - [Security](#security)
    - [HMAC Signature Calculation](#hmac-signature-calculation)
    - [Protection Features](#protection-features)
    - [Security Best Practices](#security-best-practices)
  - [API Reference](#api-reference)
    - [Types](#types)
      - [AuthConfig](#authconfig)
    - [Constants](#constants)
    - [Functions](#functions)
      - [NewAuthClient (Recommended)](#newauthclient-recommended)
      - [Client Options](#client-options)
      - [NewAuthConfig](#newauthconfig)
      - [Verify](#verify)
  - [Testing](#testing)
    - [Test Coverage](#test-coverage)
  - [Development](#development)
    - [Prerequisites](#prerequisites)
    - [Project Structure](#project-structure)
    - [Makefile Commands](#makefile-commands)
    - [CI/CD Pipeline](#cicd-pipeline)
  - [Contributing](#contributing)
    - [Code Standards](#code-standards)
  - [License](#license)
  - [Author](#author)

## Why

**Why do you need HTTP request authentication?**

In modern distributed systems and microservices architectures, securing HTTP communication between services is critical:

- **Prevent Unauthorized Access**: Ensure only authenticated clients can access your APIs
- **Protect Against Replay Attacks**: Time-based signatures prevent attackers from reusing captured requests
- **Maintain Request Integrity**: Cryptographic signatures detect any tampering with request data
- **Secure Query Parameters**: Include URL parameters in signatures to prevent manipulation
- **Flexible Security Levels**: Choose the right authentication strategy for your use case

Without proper authentication, your APIs are vulnerable to:

- Unauthorized access and data breaches
- Man-in-the-middle attacks
- Request tampering and parameter injection
- Replay attacks using captured requests

## What

**go-httpclient** is a Go package that provides **configurable HTTP authentication mechanisms** for both client-side request signing and server-side request verification.

### Three Authentication Modes

1. **None Mode** (`AuthModeNone`)
   - No authentication headers added
   - Use for public endpoints or when authentication is handled elsewhere

2. **Simple Mode** (`AuthModeSimple`)
   - API secret key sent in a custom header
   - Lightweight authentication for internal services
   - Default header: `X-API-Secret` (customizable)

3. **HMAC Mode** (`AuthModeHMAC`)
   - HMAC-SHA256 cryptographic signatures
   - Three headers: signature, timestamp, and nonce
   - Includes request method, path, query parameters, and body in signature
   - Built-in replay attack prevention with timestamp validation
   - Default headers: `X-Signature`, `X-Timestamp`, `X-Nonce` (all customizable)

### Key Benefits

- **Automatic Authentication**: One-line client creation with built-in request signing via `NewAuthClient`
- **Flexible Configuration**: Option Pattern for easy customization without breaking changes
  - Client options: `WithTimeout`, `WithMaxBodySize`, `WithSkipAuthFunc`, `WithHMACHeaders`, etc.
  - Verification options: `WithVerifyMaxAge`, `WithVerifyMaxBodySize`
- **Custom TLS Certificates**: Load certificates from files, URLs, or embedded content for enterprise PKI
- **DoS Protection**: Configurable body size limits prevent memory exhaustion attacks (default: 10MB)
- **Zero Dependencies** (except `google/uuid` for nonce generation)
- **Simple API**: Easy to integrate into existing HTTP clients
- **Dual Purpose**: Works for both client-side signing and server-side verification
- **Customizable**: Override default header names to match your API standards
- **Production Ready**: 90%+ test coverage, comprehensive linting, and security scanning
- **Well Tested**: 1200+ lines of test code covering all scenarios

## How

### Installation

```bash
go get github.com/appleboy/go-httpclient
```

### Quick Start

Automatic Authentication with `NewAuthClient`:

```go
package main

import (
    "bytes"
    "fmt"

    "github.com/appleboy/go-httpclient"
)

func main() {
    // Create authenticated HTTP client
    client := httpclient.NewAuthClient(httpclient.AuthModeHMAC, "your-secret-key")

    // Send request - authentication headers added automatically!
    body := []byte(`{"user": "john"}`)
    resp, err := client.Post(
        "https://api.example.com/users",
        "application/json",
        bytes.NewReader(body),
    )
    if err != nil {
        panic(err)
    }
    defer resp.Body.Close()

    fmt.Println("Request sent with automatic HMAC authentication")
}
```

### Usage Examples

For complete, runnable examples, see the [`_example`](_example/) directory. Each example includes detailed documentation and can be run independently.

#### No Authentication

For public endpoints or when authentication is not required:

```go
client := httpclient.NewAuthClient(httpclient.AuthModeNone, "")
resp, err := client.Get("https://api.example.com/public")
// No authentication headers added
```

#### Simple API Key Authentication

For basic authentication with a shared secret:

```go
// Create client with simple authentication (default header: X-API-Secret)
client := httpclient.NewAuthClient(httpclient.AuthModeSimple, "my-secret-key")

// Make requests - authentication is automatic
resp, err := client.Get("https://api.example.com/data")

// Request will automatically include:
// X-API-Secret: my-secret-key
```

**See full example:** [`_example/01-simple-auth`](_example/01-simple-auth/)

#### HMAC Signature Authentication

For cryptographically secure request signing:

```go
// Create client with HMAC authentication
client := httpclient.NewAuthClient(httpclient.AuthModeHMAC, "shared-secret")

// Make requests - authentication is automatic
body := []byte(`{"action": "transfer", "amount": 100}`)
resp, err := client.Post(
    "https://api.example.com/transactions?user=123",
    "application/json",
    bytes.NewReader(body),
)

// Request will automatically include:
// X-Signature: a3c8f9b2... (HMAC-SHA256 signature)
// X-Timestamp: 1704067200 (Unix timestamp)
// X-Nonce: 550e8400-e29b-41d4-a716-446655440000 (UUID v4)
```

The signature is calculated as:

```txt
HMAC-SHA256(secret, timestamp + method + path + query + body)
```

For example:

```txt
message = "1704067200POST/transactions?user=123{\"action\":\"transfer\",\"amount\":100}"
signature = HMAC-SHA256("shared-secret", message)
```

**See full example:** [`_example/02-hmac-auth`](_example/02-hmac-auth/)

#### Custom Header Names

Override default header names to match your API standards:

```go
// Simple mode with custom header name
client := httpclient.NewAuthClient(
    httpclient.AuthModeSimple,
    "my-key",
    httpclient.WithHeaderName("Authorization"),
)
// Requests will include:
// Authorization: my-key
```

For HMAC mode:

```go
// HMAC mode with custom header names
client := httpclient.NewAuthClient(
    httpclient.AuthModeHMAC,
    "secret",
    httpclient.WithHMACHeaders("X-Custom-Signature", "X-Request-Time", "X-Request-ID"),
)
// Requests will include custom header names
```

**See full example:** [`_example/03-custom-headers`](_example/03-custom-headers/)

#### Server-Side Verification

Verify authentication on the server side with the unified `Verify()` method:

```go
func authMiddleware(next http.Handler) http.Handler {
    return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
        // Create auth config with same mode and secret as client
        auth := httpclient.NewAuthConfig(httpclient.AuthModeHMAC, "shared-secret")

        // Verify automatically selects the right verification based on mode
        // Use defaults (5 minutes max age, 10MB max body size)
        if err := auth.Verify(r); err != nil {
            http.Error(w, "Authentication failed: "+err.Error(), http.StatusUnauthorized)
            return
        }

        // Authentication is valid, proceed to next handler
        next.ServeHTTP(w, r)
    })
}

func main() {
    mux := http.NewServeMux()
    mux.HandleFunc("/api/secure", func(w http.ResponseWriter, r *http.Request) {
        // Your secure handler code
        w.Write([]byte("Access granted"))
    })

    // Wrap with authentication middleware
    http.ListenAndServe(":8080", authMiddleware(mux))
}
```

**Customize Verification Options (HMAC mode only):**

```go
// Strict API endpoint - 2 minute timeout, 1MB limit
if err := auth.Verify(r,
    httpclient.WithVerifyMaxAge(2*time.Minute),
    httpclient.WithVerifyMaxBodySize(1*1024*1024),
); err != nil {
    return err
}

// File upload endpoint - 10 minute timeout, 50MB limit
if err := auth.Verify(r,
    httpclient.WithVerifyMaxAge(10*time.Minute),
    httpclient.WithVerifyMaxBodySize(50*1024*1024),
); err != nil {
    return err
}

// Custom max age only (use default 10MB body limit)
if err := auth.Verify(r,
    httpclient.WithVerifyMaxAge(15*time.Minute),
); err != nil {
    return err
}
```

**Available Verification Options:**

- `WithVerifyMaxAge(duration)` - Maximum age for request timestamps (default: 5 minutes)
- `WithVerifyMaxBodySize(bytes)` - Maximum request body size to prevent DoS attacks (default: 10MB)

**See full example:** [`_example/04-server-verification`](_example/04-server-verification/)

#### Automatic Authentication with RoundTripper

The simplest way to use this package - create an HTTP client that automatically signs all requests:

```go
// Create authenticated client with automatic signing
client := httpclient.NewAuthClient(httpclient.AuthModeHMAC, "secret")

// Use it like a normal http.Client - authentication is automatic!
resp, err := client.Post(
    "https://api.example.com/data",
    "application/json",
    bytes.NewReader([]byte(`{"key": "value"}`)),
)
```

**With Configuration Options:**

```go
client := httpclient.NewAuthClient(
    httpclient.AuthModeHMAC,
    "secret",
    httpclient.WithTimeout(10*time.Second),
    httpclient.WithMaxBodySize(5*1024*1024), // 5MB limit
    httpclient.WithSkipAuthFunc(func(req *http.Request) bool {
        // Skip authentication for health checks
        return strings.HasPrefix(req.URL.Path, "/health")
    }),
)
```

**Available Options:**

- `WithTimeout(duration)` - Set request timeout (default: 30s)
- `WithMaxBodySize(bytes)` - Limit request body size (default: 10MB)
- `WithTransport(transport)` - Use custom HTTP transport
- `WithSkipAuthFunc(func)` - Conditionally skip authentication
- `WithHMACHeaders(sig, ts, nonce)` - Custom HMAC header names
- `WithHeaderName(name)` - Custom header for simple mode
- `WithTLSCertFromFile(path)` - Load TLS certificate from file
- `WithTLSCertFromURL(ctx, url)` - Download TLS certificate from URL (with context for timeout control)
- `WithTLSCertFromBytes(pem)` - Load TLS certificate from bytes
- `WithInsecureSkipVerify(bool)` - Skip TLS certificate verification (testing only)

**See full examples:**

- [`_example/05-roundtripper-client`](_example/05-roundtripper-client/) - Basic automatic authentication
- [`_example/06-options-showcase`](_example/06-options-showcase/) - All configuration options
- [`_example/07-transport-chaining`](_example/07-transport-chaining/) - Advanced transport composition

#### Custom TLS Certificates

For enterprise environments with custom Certificate Authorities or self-signed certificates:

```go
// Load certificate from file
client := httpclient.NewAuthClient(
    httpclient.AuthModeHMAC,
    "secret",
    httpclient.WithTLSCertFromFile("/etc/ssl/certs/company-ca.crt"),
)

// Load certificate from URL with timeout control
ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
defer cancel()
client := httpclient.NewAuthClient(
    httpclient.AuthModeHMAC,
    "secret",
    httpclient.WithTLSCertFromURL(ctx, "https://internal-ca.company.com/ca.crt"),
)

// Load certificate from embedded content
certPEM := []byte(`-----BEGIN CERTIFICATE-----
MIIDXTCCAkWgAwIBAgIJAKL0UG+mRKmdMA0GCSqGSIb3DQEBCwUAMEUx...
-----END CERTIFICATE-----`)

client := httpclient.NewAuthClient(
    httpclient.AuthModeHMAC,
    "secret",
    httpclient.WithTLSCertFromBytes(certPEM),
)

// Load multiple certificates for certificate chain
client := httpclient.NewAuthClient(
    httpclient.AuthModeHMAC,
    "secret",
    httpclient.WithTLSCertFromFile("/etc/ssl/certs/root-ca.crt"),
    httpclient.WithTLSCertFromFile("/etc/ssl/certs/intermediate-ca.crt"),
)

// Skip TLS verification (testing/development only - NOT RECOMMENDED for production)
client := httpclient.NewAuthClient(
    httpclient.AuthModeHMAC,
    "secret",
    httpclient.WithInsecureSkipVerify(true),
)
```

**Key Features:**

- Load certificates from files, URLs, or byte content
- Multiple certificates supported for chain verification
- System certificate pool preserved (custom certs added)
- TLS 1.2+ enforced for security
- 1MB size limit prevents memory exhaustion attacks
- Configuration errors cause immediate panic for fail-fast behavior
- Skip TLS verification for testing (use with caution)

**See full example:** [`examples/custom_cert`](examples/custom_cert/)

## Features

- **Automatic Authentication**: RoundTripper-based client signs requests automatically
- **Flexible Configuration**: Option Pattern for easy customization (timeout, body limits, etc.)
  - **Client Options**: `WithTimeout`, `WithMaxBodySize`, `WithTransport`, `WithSkipAuthFunc`, etc.
  - **Verification Options**: `WithVerifyMaxAge`, `WithVerifyMaxBodySize` for per-endpoint control
- **Multiple Authentication Strategies**: Choose between none, simple, or HMAC modes
- **Custom TLS Certificates**: Load certificates from files, URLs, or embedded content
- **Enterprise PKI Support**: Trust custom Certificate Authorities and self-signed certificates
- **Cryptographic Security**: HMAC-SHA256 signatures with constant-time comparison
- **Replay Attack Protection**: Timestamp validation prevents reuse of old requests
- **Query Parameter Security**: Include URL parameters in signature to prevent tampering
- **Request Integrity**: Signature covers method, path, query, and body
- **Body Preservation**: Request body is restored after verification for downstream handlers
- **Transport Chaining**: Compatible with logging, metrics, and custom transports
- **Conditional Authentication**: Skip auth for specific endpoints (e.g., health checks)
- **DoS Protection**: Configurable body size limits prevent memory exhaustion attacks
  - Default: 10MB limit for verification
  - Per-endpoint customization: strict APIs (1MB) vs. file uploads (50MB)
  - Early rejection with `io.LimitReader` for safe, bounded reading
- **Customizable Headers**: Override default header names to match your API conventions
- **Dual Purpose**: Same package for client signing and server verification
- **Zero Config Defaults**: Sensible defaults with optional customization
- **Production Ready**: 90%+ test coverage, comprehensive linting, and security scanning

## Security

### HMAC Signature Calculation

The HMAC signature includes all critical request components:

```txt
message = timestamp + method + path + query + body
signature = HMAC-SHA256(secret, message)
```

**Example:**

```txt
Request: POST /api/users?role=admin
Body: {"name": "John"}
Timestamp: 1704067200
Secret: my-secret

Message: "1704067200POST/api/users?role=admin{\"name\":\"John\"}"
Signature: HMAC-SHA256("my-secret", message)
```

### Protection Features

1. **Replay Attack Prevention**
   - Each request includes a timestamp
   - Server validates timestamp is within acceptable window (default: 5 minutes)
   - Old signatures cannot be reused

2. **Request Tampering Detection**
   - Any modification to method, path, query, or body invalidates signature
   - Cryptographic verification ensures request integrity

3. **Query Parameter Security**
   - Query parameters are included in signature calculation
   - Prevents attackers from adding/modifying/removing parameters

4. **Constant-Time Comparison**
   - Uses `hmac.Equal()` to prevent timing attacks
   - Secure against side-channel attacks

5. **Memory Exhaustion Protection (DoS Prevention)**
   - **Request Body Size Limits**: Configurable per-endpoint (default: 10MB)
     - Prevents attackers from sending massive payloads
     - Uses `io.LimitReader` for safe, bounded reading
     - Returns clear error message when limit exceeded
   - **TLS Certificate Size Limits**: Maximum 1MB for certificate files
   - **Fail-Fast Validation**: Early rejection before processing malicious requests

   **Example Configuration:**

   ```go
   // Strict API: 1MB limit
   auth.Verify(req, httpclient.WithVerifyMaxBodySize(1*1024*1024))

   // File upload API: 50MB limit
   auth.Verify(req, httpclient.WithVerifyMaxBodySize(50*1024*1024))
   ```

### Security Best Practices

- Use HTTPS (TLS) for all requests to protect secrets in transit
- Rotate shared secrets regularly
- Use strong, random secrets (minimum 32 bytes)
- Set appropriate timestamp validation windows (default 5 minutes)
- Monitor and log authentication failures
- Use HMAC mode for production environments

## API Reference

### Types

#### AuthConfig

Main configuration struct for authentication:

```go
type AuthConfig struct {
    Mode            string // "none", "simple", or "hmac"
    Secret          string // Shared secret key
    HeaderName      string // Custom header for simple mode (default: "X-API-Secret")
    SignatureHeader string // Signature header for HMAC (default: "X-Signature")
    TimestampHeader string // Timestamp header for HMAC (default: "X-Timestamp")
    NonceHeader     string // Nonce header for HMAC (default: "X-Nonce")
}
```

### Constants

```go
const (
    AuthModeNone   = "none"   // No authentication
    AuthModeSimple = "simple" // Simple API secret in header
    AuthModeHMAC   = "hmac"   // HMAC-SHA256 signature
)
```

### Functions

#### NewAuthClient (Recommended)

```go
func NewAuthClient(mode, secret string, opts ...ClientOption) *http.Client
```

Creates an HTTP client with automatic authentication. All requests are signed automatically based on the configured mode.

**Parameters:**

- `mode`: Authentication mode (`AuthModeNone`, `AuthModeSimple`, or `AuthModeHMAC`)
- `secret`: Shared secret key
- `opts`: Optional configuration (timeout, body limits, custom headers, etc.)

**Returns:** Configured `*http.Client` with automatic authentication

**Example:**

```go
client := httpclient.NewAuthClient(
    httpclient.AuthModeHMAC,
    "secret",
    httpclient.WithTimeout(10*time.Second),
    httpclient.WithMaxBodySize(5*1024*1024),
)
```

#### Client Options

Configure `NewAuthClient` behavior:

**General Options:**

- `WithTimeout(duration)` - Request timeout (default: 30s)
- `WithMaxBodySize(bytes)` - Max body size (default: 10MB, set 0 for unlimited)
- `WithTransport(transport)` - Custom base transport
- `WithSkipAuthFunc(func(*http.Request) bool)` - Skip auth conditionally

**Authentication Options:**

- `WithHMACHeaders(sig, ts, nonce string)` - Custom HMAC header names
- `WithHeaderName(name string)` - Custom header for simple mode

**TLS Certificate Options:**

- `WithTLSCertFromFile(path string)` - Load certificate from file path
- `WithTLSCertFromURL(ctx context.Context, url string)` - Download certificate from URL with context for timeout control
- `WithTLSCertFromBytes(certPEM []byte)` - Load certificate from byte content
- `WithInsecureSkipVerify(skip bool)` - Skip TLS certificate verification (WARNING: Use only for testing/development, never in production)

**Example:**

```go
client := httpclient.NewAuthClient(
    httpclient.AuthModeHMAC,
    "secret",
    httpclient.WithTimeout(30*time.Second),
    httpclient.WithTLSCertFromFile("/etc/ssl/certs/company-ca.crt"),
)

// For testing with self-signed certificates (NOT for production)
testClient := httpclient.NewAuthClient(
    httpclient.AuthModeHMAC,
    "secret",
    httpclient.WithInsecureSkipVerify(true),
)
```

#### NewAuthConfig

```go
func NewAuthConfig(mode, secret string) *AuthConfig
```

Creates a new `AuthConfig` with default header names. This is primarily used for server-side verification with the `Verify()` method.

**Parameters:**

- `mode`: Authentication mode (`AuthModeNone`, `AuthModeSimple`, or `AuthModeHMAC`)
- `secret`: Shared secret key (must match the client's secret)

**Returns:** Configured `*AuthConfig` with defaults

**Example:**

```go
// Server-side verification
auth := httpclient.NewAuthConfig(httpclient.AuthModeHMAC, "shared-secret")
if err := auth.Verify(req); err != nil {
    http.Error(w, "Authentication failed", http.StatusUnauthorized)
    return
}
```

#### Verify

```go
func (c *AuthConfig) Verify(req *http.Request, opts ...VerifyOption) error
```

Verifies authentication from an HTTP request (server-side validation). This is the unified verification method that automatically selects the appropriate verification logic based on the configured authentication mode.

**Supported Modes:**

- `AuthModeNone`: No verification performed, returns nil immediately
- `AuthModeSimple`: Verifies the API secret in the configured header
- `AuthModeHMAC`: Verifies HMAC signature with timestamp and body validation

**Parameters:**

- `req`: HTTP request to verify
- `opts`: Optional configuration (only applies to HMAC mode)

**Returns:** Error if verification fails or signature is invalid

**Available Options (HMAC mode only):**

- `WithVerifyMaxAge(duration)` - Maximum age for request timestamps (default: 5 minutes)
- `WithVerifyMaxBodySize(bytes)` - Maximum request body size to prevent DoS attacks (default: 10MB)

**Examples:**

```go
// Simple mode verification
auth := httpclient.NewAuthConfig(httpclient.AuthModeSimple, "secret")
err := auth.Verify(req)

// HMAC mode with defaults (5 minutes, 10MB)
auth := httpclient.NewAuthConfig(httpclient.AuthModeHMAC, "secret")
err := auth.Verify(req)

// HMAC mode with custom max age only
err := auth.Verify(req,
    httpclient.WithVerifyMaxAge(10*time.Minute),
)

// HMAC mode with custom body size limit only
err := auth.Verify(req,
    httpclient.WithVerifyMaxBodySize(5*1024*1024),
)

// HMAC mode with multiple options
err := auth.Verify(req,
    httpclient.WithVerifyMaxAge(10*time.Minute),
    httpclient.WithVerifyMaxBodySize(50*1024*1024),
)
```

**Security Features (HMAC mode):**

- **Body Size Limit**: Prevents memory exhaustion DoS attacks (default: 10MB)
- **Timestamp Validation**: Rejects requests older than max age (default: 5 minutes)
- **Clock Skew Protection**: Rejects requests with future timestamps beyond max age
- **Constant-Time Comparison**: Uses `hmac.Equal()` to prevent timing attacks
- **Body Preservation**: Request body is restored for subsequent handlers

## Testing

Run tests with coverage:

```bash
make test
```

Run linting and formatting:

```bash
make lint
make fmt
```

### Test Coverage

The package includes comprehensive tests covering:

- All three authentication modes
- Custom header names
- Signature calculation consistency
- Server-side verification
- Invalid signature rejection
- Timestamp expiration
- Missing header validation
- Body preservation after verification
- Query parameter tampering prevention
- **Body size limit protection** (new)
  - Requests within limit accepted
  - Requests exceeding limit rejected
  - Exact limit boundary testing
  - Default 10MB limit validation
  - Custom size limit configuration
  - Multiple options combination
- TLS certificate loading from files, URLs, and bytes
- Multiple certificate chain verification
- Certificate error handling
- Options Pattern API usage

**Coverage:** 90.1% of statements

View coverage report:

```bash
go test -coverprofile=coverage.txt
go tool cover -html=coverage.txt
```

## Development

### Prerequisites

- Go 1.24 or higher
- Make (optional, for convenience)

### Project Structure

```txt
.
├── auth.go              # Core authentication implementation
├── auth_test.go         # Authentication tests (560+ lines)
├── client.go            # RoundTripper-based HTTP client
├── client_test.go       # Client tests (660+ lines)
├── cert_test.go         # TLS certificate tests (360+ lines)
├── go.mod               # Module definition
├── Makefile            # Build automation
├── .golangci.yml       # Linting configuration
├── _example/           # Runnable examples
│   ├── 01-simple-auth/           # Simple API key authentication
│   ├── 02-hmac-auth/             # HMAC signature authentication
│   ├── 03-custom-headers/        # Custom header names
│   ├── 04-server-verification/   # Server-side verification
│   ├── 05-roundtripper-client/   # Automatic authentication
│   ├── 06-options-showcase/      # Configuration options
│   └── 07-transport-chaining/    # Transport composition
├── examples/           # Additional examples
│   └── custom_cert/    # Custom TLS certificate examples
└── .github/workflows/  # CI/CD pipelines
    ├── testing.yml     # Multi-platform testing
    ├── security.yml    # Trivy security scanning
    └── codeql.yml      # Code quality analysis
```

### Makefile Commands

```bash
make test    # Run tests with coverage
make fmt     # Format code with golangci-lint
make lint    # Run linting checks
make clean   # Remove coverage artifacts
make help    # Show all commands
```

### CI/CD Pipeline

- **Testing**: Runs on Go 1.24 and 1.25, on Ubuntu and macOS
- **Security**: Daily Trivy scans for vulnerabilities
- **Code Quality**: CodeQL analysis for Go best practices
- **Coverage**: Automatic upload to Codecov

## Contributing

Contributions are welcome! Please follow these guidelines:

1. Fork the repository
2. Create a feature branch (`git checkout -b feature/amazing-feature`)
3. Make your changes
4. Run tests and linting (`make test lint`)
5. Commit your changes (`git commit -m 'Add amazing feature'`)
6. Push to the branch (`git push origin feature/amazing-feature`)
7. Open a Pull Request

### Code Standards

- Follow Go best practices and idioms
- Maintain test coverage above 80%
- Pass all linting checks (golangci-lint)
- Add tests for new features
- Update documentation as needed

## License

This project is licensed under the MIT License - see the [LICENSE](LICENSE) file for details.

Copyright (c) 2026 Bo-Yi Wu

## Author

- GitHub: [@appleboy](https://github.com/appleboy)
- Website: [https://blog.wu-boy.com](https://blog.wu-boy.com)

Support this project:

[![Donate](https://img.shields.io/badge/Donate-PayPal-green.svg)](https://www.paypal.me/appleboy46)
