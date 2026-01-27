# CLAUDE.md

This file provides guidance to Claude Code (claude.ai/code) when working with code in this repository.

## Project Overview

`go-httpclient` is a lightweight Go package for HTTP request authentication. It provides four authentication modes: none (public endpoints), simple (API secret in header), HMAC-SHA256 (cryptographic signatures with replay attack prevention), and GitHub (webhook-compatible HMAC-SHA256). The package serves dual purposes: client-side request signing and server-side request verification.

## Go Version

- Minimum required: Go 1.24
- CI tests against: Go 1.24 and 1.25
- Use `go.mod` module name: `httpclient`

## Development Commands

### Testing

```bash
make test              # Run tests with coverage (generates coverage.txt)
go test -v -cover -coverprofile coverage.txt ./...
```

### Linting and Formatting

```bash
make lint              # Run golangci-lint checks
make fmt               # Format code with golangci-lint
```

### Cleanup

```bash
make clean             # Remove coverage.txt
```

### View Test Coverage

```bash
go tool cover -html=coverage.txt
```

## Code Architecture

### Core Components

**auth.go** (~360 lines): Core authentication implementation:

- `AuthConfig`: Main configuration struct with authentication mode, secret, and customizable header names
- `NewAuthConfig()`: Factory function to create AuthConfig for server-side verification
- Public verification method: `Verify()` validates incoming requests for all authentication modes
- Private methods:
  - `addAuthHeaders()`: Adds authentication headers (used internally by authRoundTripper)
  - `verifySimpleAuth()`: Validates Simple mode authentication
  - `verifyHMACSignature()`: Validates HMAC mode authentication with options
- HMAC signature calculation: `calculateHMACSignature()` computes signatures from timestamp + method + full path (including query) + body

**client.go** (~760 lines): RoundTripper-based HTTP client with automatic authentication:

- `NewAuthClient(mode, secret, ...opts) (*http.Client, error)`: Creates http.Client with automatic authentication using Option Pattern. **Returns error** if any option fails (e.g., certificate file not found, invalid mTLS cert/key pair).
- `authRoundTripper`: Implements http.RoundTripper interface for transparent request signing
- Option Pattern functions: `WithTimeout()`, `WithMaxBodySize()`, `WithTransport()`, `WithSkipAuthFunc()`, `WithHMACHeaders()`, `WithHeaderName()`
- TLS certificate options: `WithTLSCertFromFile()`, `WithTLSCertFromURL()`, `WithTLSCertFromBytes()` - Load custom CA certificates
- TLS skip verification: `WithInsecureSkipVerify()` - Skip TLS certificate verification for testing/development
- mTLS certificate options: `WithMTLSFromFile()`, `WithMTLSFromBytes()` - Load client certificates for mutual TLS authentication
- Automatic body reading and restoration: Reads request body for signature calculation, then restores it for the underlying transport
- Security features: Body size limits (default 10MB), conditional authentication skipping, configurable timeouts, mTLS support, insecure skip verify option

### Authentication Flow

**Client-side signing (automatic):**

1. Create authenticated client: `client, err := NewAuthClient(mode, secret, ...opts)` (handle error if options fail)
2. Make requests normally: `client.Get(url)` or `client.Post(url, contentType, body)`
3. Authentication headers are automatically added by the RoundTripper
4. Body is automatically read, signed, and restored
5. Headers are added based on mode (simple: one header, HMAC: three headers)

**Server-side verification:**

1. Create `AuthConfig` with same mode and secret as client
2. Call `Verify(req, ...opts)` in middleware
3. Verification method is automatically selected based on mode:
   - `AuthModeNone`: No verification performed
   - `AuthModeSimple`: Verifies API secret in header
   - `AuthModeHMAC`: Verifies signature, timestamp, and body
   - `AuthModeGitHub`: Verifies GitHub-style signature and body
4. For HMAC/GitHub modes: Body is read and restored to `req.Body` for downstream handlers
5. For HMAC mode: Timestamp checked against options (default: 5 minutes)
6. For GitHub mode: No timestamp validation (webhook compatibility)

### HMAC Signature Components

Signature includes all critical request parts to prevent tampering:

```txt
message = timestamp + method + path + query + body
signature = HMAC-SHA256(secret, message)
```

Example: `"1704067200POST/api/users?role=admin{\"name\":\"John\"}"`

Query parameters are intentionally included in signature to prevent parameter injection attacks.

### GitHub Webhook-Style Mode

**Purpose**: Compatible with GitHub webhook signature format and other webhook providers using similar HMAC-SHA256 patterns.

**Signature Format**:

```txt
message = body
signature = "sha256=" + HMAC-SHA256(secret, body)
```

**Key Differences from HMAC Mode**:

- Signature includes ONLY the request body
- Signature has "sha256=" prefix
- Single header (X-Hub-Signature-256) instead of three
- No timestamp validation (no replay attack protection)

**Client-side signing (automatic)**:

```go
client := httpclient.NewAuthClient(httpclient.AuthModeGitHub, secret)
client.Post(url, contentType, body)
// Adds header: X-Hub-Signature-256: sha256=<hex_digest>
```

**Server-side verification**:

```go
auth := httpclient.NewAuthConfig(httpclient.AuthModeGitHub, secret)
if err := auth.Verify(req); err != nil {
    // Signature invalid
}
```

**Security Limitations**:

- ⚠️ No timestamp validation (GitHub webhooks don't provide timestamps)
- ⚠️ Vulnerable to replay attacks without additional safeguards
- ✅ Mitigation: Use HTTPS + regular secret rotation

**Python Compatibility**: Fully compatible with the standard Python GitHub webhook verification pattern.

## Verification API Design

The library provides a unified `Verify()` method for server-side authentication validation:

**Public API:**

- `Verify(req *http.Request, opts ...VerifyOption) error` - Unified verification method that automatically dispatches to the appropriate verification logic based on `AuthConfig.Mode`

**Private Methods (internal use only):**

- `verifySimpleAuth(req *http.Request) error` - Validates Simple mode authentication
- `verifyHMACSignature(req *http.Request, opts ...VerifyOption) error` - Validates HMAC mode authentication
- `verifyGitHubSignature(req *http.Request, opts ...VerifyOption) error` - Validates GitHub mode authentication

**Design Rationale:**

- Provides a single, consistent API for all authentication modes
- Automatically selects the correct verification based on configuration
- Internal methods keep implementation details private
- Options Pattern allows flexible configuration for HMAC mode

## Testing Requirements

- Comprehensive test coverage in `auth_test.go` (1400+ lines), `client_test.go` (~660 lines), and `cert_test.go` (~570 lines)
- `auth_test.go`: Tests all four modes, custom headers, unified Verify() method, mode-specific verification, timestamp expiration, query parameter security, body size limits, GitHub webhook compatibility
- `client_test.go`: Tests RoundTripper implementation, Option Pattern, body preservation, transport chaining, error handling, mTLS support
- `cert_test.go`: Tests custom TLS certificate loading from files/URLs/bytes, error handling for invalid certificates, insecure skip verify option, mTLS certificate loading and validation
- Integration tests use `httptest.NewServer` and `httptest.NewUnstartedServer` with custom TLS configs for end-to-end validation
- All tests must pass on both Ubuntu and macOS
- Current coverage: ~90% (exceeds 80% minimum requirement)

## Linting Configuration

Uses `.golangci.yml` with strict linters enabled:

- Security: `gosec` for security issues
- Quality: `staticcheck`, `govet`, `gocritic`, `gocyclo`
- Correctness: `errcheck`, `bodyclose`, `rowserrcheck`
- Formatters: `gofmt`, `gofumpt`, `goimports`, `golines`

All new code must pass linting without warnings.

## Security Considerations

- Use `hmac.Equal()` for constant-time signature comparison (prevents timing attacks)
- Body must be preserved after verification: read body, then restore with `io.NopCloser(bytes.NewBuffer(body))`
- Query parameters must be included in signature via `getFullPath(req)` helper
- Timestamp validation prevents replay attacks
- Default 5-minute timestamp window balances security and clock skew tolerance

## CI/CD Pipeline

Three GitHub Actions workflows:

- **testing.yml**: Runs `make test` on Ubuntu/macOS with Go 1.24/1.25, uploads coverage to Codecov
- **security.yml**: Daily Trivy security scanning
- **codeql.yml**: CodeQL analysis for Go best practices

All PRs must pass CI checks.

## Dependencies

Minimal dependencies by design:

- `github.com/google/uuid`: For nonce generation in HMAC mode only
- Standard library: `crypto/hmac`, `crypto/sha256`, `net/http`, `time`

Avoid adding new dependencies unless absolutely necessary.
