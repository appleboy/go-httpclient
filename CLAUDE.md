# CLAUDE.md

This is an HTTP request authentication library that provides four authentication modes: None, Simple, HMAC-SHA256, and GitHub webhook.

## Quick Start

```bash
go get github.com/appleboy/go-httpclient
make test
go run _example/01-simple-auth/main.go  # 10 examples in _example/
```

## Commands

```bash
make help              # Show all available make targets
make test              # Run tests (generates coverage.txt)
make lint              # Run golangci-lint checks
make fmt               # Format code
go tool cover -html=coverage.txt  # View test coverage
```

## Code Structure

- **auth.go** (~500 lines): `AuthConfig`, `Verify()`, four authentication mode implementations
- **client.go** (~340 lines): `NewAuthClient()`, `authRoundTripper` (implements RoundTripper interface)
- **option.go** (~550 lines): All Option Pattern functions (`WithTimeout`, `WithTLS*`, `WithMTLS*`)

## Examples

`_example/` directory contains 10 standalone examples:

1. **01-simple-auth**: Basic API key authentication
2. **02-hmac-auth**: HMAC-SHA256 signature authentication
3. **03-custom-headers**: Custom header names
4. **04-server-verification**: Server-side verification middleware
5. **05-roundtripper-client**: Direct RoundTripper interface usage
6. **06-options-showcase**: Various client options
7. **07-transport-chaining**: Chaining multiple RoundTrippers
8. **08-custom-cert**: Loading custom TLS certificates
9. **09-mtls**: Mutual TLS authentication setup
10. **10-request-id-tracking**: Request ID tracking for distributed tracing

Run examples: `go run _example/<example-name>/main.go`

## Security Gotchas

**Critical patterns** (violating these patterns causes security vulnerabilities):

- **Timing attack defense**: Use `hmac.Equal()` for signature comparison (never `==` or `bytes.Equal()`)
- **Body preservation**: Must restore body after verification: `io.NopCloser(bytes.NewBuffer(body))`
- **Query parameter protection**: Signature must include query parameters via `getFullPath(req)` helper
- **Replay attack defense**: HMAC mode uses 5-minute time window by default (balances security and clock skew)
- **GitHub mode limitation**: No timestamp validation, vulnerable to replay attacks without HTTPS + regular secret rotation

## Dependencies

**Minimal by design** - only one external dependency:

- `github.com/google/uuid`: For HMAC mode nonce generation
- Everything else uses stdlib: `crypto/hmac`, `crypto/sha256`, `net/http`, `time`

**Important**: Justify thoroughly before adding new dependencies.

## CI Requirements

- Go 1.24 minimum version, CI tests 1.24 and 1.25
- All tests must pass on both Ubuntu and macOS
- Test coverage must be >80% (currently ~90%)
- All PRs must pass golangci-lint with zero warnings
