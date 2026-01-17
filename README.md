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
      - [NewAuthConfig](#newauthconfig)
      - [AddAuthHeaders](#addauthheaders)
      - [VerifyHMACSignature](#verifyhmacsignature)
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

- **Zero Dependencies** (except `google/uuid` for nonce generation)
- **Simple API**: Easy to integrate into existing HTTP clients
- **Dual Purpose**: Works for both client-side signing and server-side verification
- **Customizable**: Override default header names to match your API standards
- **Production Ready**: Comprehensive test coverage and security scanning
- **Well Tested**: 560+ lines of test code covering all scenarios

## How

### Installation

```bash
go get github.com/appleboy/go-httpclient
```

### Quick Start

```go
package main

import (
    "bytes"
    "fmt"
    "net/http"

    "github.com/appleboy/go-httpclient"
)

func main() {
    // Create auth config with HMAC mode
    auth := httpclient.NewAuthConfig(httpclient.AuthModeHMAC, "your-secret-key")

    // Create HTTP request
    body := []byte(`{"user": "john"}`)
    req, _ := http.NewRequest("POST", "https://api.example.com/users", bytes.NewReader(body))

    // Add authentication headers
    if err := auth.AddAuthHeaders(req, body); err != nil {
        panic(err)
    }

    // Send request
    client := &http.Client{}
    resp, err := client.Do(req)
    if err != nil {
        panic(err)
    }
    defer resp.Body.Close()

    fmt.Println("Request sent with HMAC authentication")
}
```

### Usage Examples

#### No Authentication

For public endpoints or when authentication is not required:

```go
auth := httpclient.NewAuthConfig(httpclient.AuthModeNone, "")
req, _ := http.NewRequest("GET", "https://api.example.com/public", nil)
auth.AddAuthHeaders(req, nil) // No headers added
```

#### Simple API Key Authentication

For basic authentication with a shared secret:

```go
// Using default header name (X-API-Secret)
auth := httpclient.NewAuthConfig(httpclient.AuthModeSimple, "my-secret-key")
req, _ := http.NewRequest("GET", "https://api.example.com/data", nil)
auth.AddAuthHeaders(req, nil)

// Request will include:
// X-API-Secret: my-secret-key
```

#### HMAC Signature Authentication

For cryptographically secure request signing:

```go
auth := httpclient.NewAuthConfig(httpclient.AuthModeHMAC, "shared-secret")

body := []byte(`{"action": "transfer", "amount": 100}`)
req, _ := http.NewRequest("POST", "https://api.example.com/transactions?user=123", bytes.NewReader(body))

auth.AddAuthHeaders(req, body)

// Request will include:
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

#### Custom Header Names

Override default header names to match your API standards:

```go
auth := httpclient.NewAuthConfig(httpclient.AuthModeSimple, "my-key")
auth.HeaderName = "Authorization"

auth.AddAuthHeaders(req, nil)
// Request will include:
// Authorization: my-key
```

For HMAC mode:

```go
auth := httpclient.NewAuthConfig(httpclient.AuthModeHMAC, "secret")
auth.SignatureHeader = "X-Custom-Signature"
auth.TimestampHeader = "X-Request-Time"
auth.NonceHeader = "X-Request-ID"

auth.AddAuthHeaders(req, body)
// Request will include custom header names
```

#### Server-Side Verification

Verify HMAC signatures on the server side:

```go
func authMiddleware(next http.Handler) http.Handler {
    return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
        auth := httpclient.NewAuthConfig(httpclient.AuthModeHMAC, "shared-secret")

        // Verify signature with 5-minute maximum age
        if err := auth.VerifyHMACSignature(r, 5*time.Minute); err != nil {
            http.Error(w, "Authentication failed: "+err.Error(), http.StatusUnauthorized)
            return
        }

        // Signature is valid, proceed to next handler
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

## Features

- **Multiple Authentication Strategies**: Choose between none, simple, or HMAC modes
- **Cryptographic Security**: HMAC-SHA256 signatures with constant-time comparison
- **Replay Attack Protection**: Timestamp validation prevents reuse of old requests
- **Query Parameter Security**: Include URL parameters in signature to prevent tampering
- **Request Integrity**: Signature covers method, path, query, and body
- **Body Preservation**: Request body is restored after verification for downstream handlers
- **Customizable Headers**: Override default header names to match your API conventions
- **Dual Purpose**: Same package for client signing and server verification
- **Zero Config Defaults**: Sensible defaults with optional customization
- **Production Ready**: Comprehensive tests, linting, and security scanning

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

#### NewAuthConfig

```go
func NewAuthConfig(mode, secret string) *AuthConfig
```

Creates a new `AuthConfig` with default header names.

**Parameters:**

- `mode`: Authentication mode (`AuthModeNone`, `AuthModeSimple`, or `AuthModeHMAC`)
- `secret`: Shared secret key (required for simple and HMAC modes)

**Returns:** Configured `*AuthConfig` with defaults

#### AddAuthHeaders

```go
func (c *AuthConfig) AddAuthHeaders(req *http.Request, body []byte) error
```

Adds authentication headers to an HTTP request based on configured mode.

**Parameters:**

- `req`: HTTP request to add headers to
- `body`: Request body (required for HMAC signature calculation)

**Returns:** Error if authentication fails or invalid configuration

#### VerifyHMACSignature

```go
func (c *AuthConfig) VerifyHMACSignature(req *http.Request, maxAge time.Duration) error
```

Verifies HMAC signature from an HTTP request (server-side validation).

**Parameters:**

- `req`: HTTP request to verify
- `maxAge`: Maximum age for timestamp (default: 5 minutes if zero)

**Returns:** Error if verification fails or signature is invalid

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
├── auth.go              # Main authentication implementation
├── auth_test.go         # Comprehensive test suite
├── go.mod               # Module definition
├── Makefile            # Build automation
├── .golangci.yml       # Linting configuration
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
