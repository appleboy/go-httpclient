# CLAUDE.md

This file provides guidance to Claude Code (claude.ai/code) when working with code in this repository.

## Project Overview

`go-httpclient` is a lightweight Go package for HTTP request authentication. It provides three authentication modes: none (public endpoints), simple (API secret in header), and HMAC-SHA256 (cryptographic signatures with replay attack prevention). The package serves dual purposes: client-side request signing and server-side request verification.

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

**auth.go** (221 lines): Core authentication implementation:

- `AuthConfig`: Main configuration struct with authentication mode, secret, and customizable header names
- Client-side methods: `AddAuthHeaders()` adds authentication headers to outgoing requests
- Server-side methods: `VerifyHMACSignature()` validates incoming requests
- HMAC signature calculation: `calculateHMACSignature()` computes signatures from timestamp + method + full path (including query) + body

**client.go** (~290 lines): RoundTripper-based HTTP client with automatic authentication:

- `NewAuthClient(mode, secret, ...opts)`: Creates http.Client with automatic authentication using Option Pattern
- `authRoundTripper`: Implements http.RoundTripper interface for transparent request signing
- Option Pattern functions: `WithTimeout()`, `WithMaxBodySize()`, `WithTransport()`, `WithSkipAuthFunc()`, `WithHMACHeaders()`, `WithHeaderName()`
- Automatic body reading and restoration: Reads request body for signature calculation, then restores it for the underlying transport
- Security features: Body size limits (default 10MB), conditional authentication skipping, configurable timeouts

### Authentication Flow

**Client-side signing (automatic with NewAuthClient):**

1. Create authenticated client: `client := NewAuthClient(mode, secret, ...opts)`
2. Make requests normally: `client.Get(url)` or `client.Post(url, contentType, body)`
3. Authentication headers are automatically added by the RoundTripper
4. Body is automatically read, signed, and restored

**Client-side signing (manual with AddAuthHeaders):**

1. Create `AuthConfig` with mode and secret
2. Call `AddAuthHeaders(req, body)` before sending request
3. Headers are added based on mode (simple: one header, HMAC: three headers)

**Server-side verification:**

1. Create `AuthConfig` with same secret
2. Call `VerifyHMACSignature(req, maxAge)` in middleware
3. Body is read and restored to `req.Body` for downstream handlers
4. Timestamp checked against `maxAge` (default: 5 minutes)

### HMAC Signature Components

Signature includes all critical request parts to prevent tampering:

```txt
message = timestamp + method + path + query + body
signature = HMAC-SHA256(secret, message)
```

Example: `"1704067200POST/api/users?role=admin{\"name\":\"John\"}"`

Query parameters are intentionally included in signature to prevent parameter injection attacks.

## Testing Requirements

- Comprehensive test coverage in `auth_test.go` (560+ lines) and `client_test.go` (~660 lines)
- `auth_test.go`: Tests all three modes, custom headers, signature verification, timestamp expiration, query parameter security
- `client_test.go`: Tests RoundTripper implementation, Option Pattern, body preservation, transport chaining, error handling
- Integration tests use `httptest.NewServer` for end-to-end validation
- All tests must pass on both Ubuntu and macOS
- Current coverage: >90% (exceeds 80% minimum requirement)

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
