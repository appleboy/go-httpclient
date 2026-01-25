# Security Analysis and Recommendations for go-httpclient

## Executive Summary

The current implementation provides solid foundation for HMAC authentication but has several security gaps that should be addressed, particularly around nonce validation and replay attack prevention.

## Critical Issues

### 1. Nonce Not Validated (HIGH PRIORITY)

**Problem**: Nonce is generated but never checked for uniqueness
- Location: `auth.go:85` (generates), `VerifyHMACSignature` (doesn't validate)
- Impact: Requests can be replayed unlimited times within the timestamp window (5 minutes)
- Risk: High - Enables replay attacks for critical operations

**Solution**: Implement nonce tracking

```go
// Add to AuthConfig
type AuthConfig struct {
    // ... existing fields
    NonceStore NonceStore // Interface for nonce storage
}

// Nonce storage interface
type NonceStore interface {
    // Store nonce with expiration time
    Store(nonce string, expiry time.Time) error
    // Check if nonce exists (and is not expired)
    Exists(nonce string) bool
}

// In-memory implementation (for single server)
type InMemoryNonceStore struct {
    mu     sync.RWMutex
    nonces map[string]time.Time
}

func (s *InMemoryNonceStore) Store(nonce string, expiry time.Time) error {
    s.mu.Lock()
    defer s.mu.Unlock()

    // Clean expired nonces periodically
    s.cleanup()

    if _, exists := s.nonces[nonce]; exists {
        return fmt.Errorf("nonce already used")
    }

    s.nonces[nonce] = expiry
    return nil
}

func (s *InMemoryNonceStore) Exists(nonce string) bool {
    s.mu.RLock()
    defer s.mu.RUnlock()

    expiry, exists := s.nonces[nonce]
    if !exists {
        return false
    }

    // Check if expired
    if time.Now().After(expiry) {
        return false
    }

    return true
}

// Redis implementation (for distributed systems)
type RedisNonceStore struct {
    client *redis.Client
}

func (s *RedisNonceStore) Store(nonce string, expiry time.Time) error {
    duration := time.Until(expiry)
    return s.client.SetNX(ctx, "nonce:"+nonce, "1", duration).Err()
}
```

**Update VerifyHMACSignature**:
```go
func (c *AuthConfig) VerifyHMACSignature(req *http.Request, maxAge time.Duration) error {
    // ... existing code to get signature, timestamp

    // Get nonce header
    nonceHeader := c.NonceHeader
    if nonceHeader == "" {
        nonceHeader = "X-Nonce"
    }
    nonce := req.Header.Get(nonceHeader)

    if nonce == "" {
        return fmt.Errorf("missing nonce header")
    }

    // Validate nonce uniqueness
    if c.NonceStore != nil {
        if c.NonceStore.Exists(nonce) {
            return fmt.Errorf("nonce already used - potential replay attack")
        }

        // Store nonce with expiration
        expiry := time.Unix(timestamp, 0).Add(maxAge)
        if err := c.NonceStore.Store(nonce, expiry); err != nil {
            return fmt.Errorf("failed to store nonce: %w", err)
        }
    }

    // ... rest of verification
}
```

### 2. Body Size Limit Missing in Verification (MEDIUM PRIORITY)

**Problem**: `io.ReadAll` without size limit in `VerifyHMACSignature`
- Location: `auth.go:198`
- Impact: Memory exhaustion DoS attack
- Risk: Medium - Can crash server with large payloads

**Solution**: Add size limit check

```go
func (c *AuthConfig) VerifyHMACSignature(req *http.Request, maxAge time.Duration, maxBodySize int64) error {
    // Set default max body size
    if maxBodySize == 0 {
        maxBodySize = 10 * 1024 * 1024 // 10MB default
    }

    // Limit reader
    limitedReader := io.LimitReader(req.Body, maxBodySize+1)
    body, err := io.ReadAll(limitedReader)
    if err != nil {
        return fmt.Errorf("failed to read body: %w", err)
    }

    // Check if body exceeded limit
    if int64(len(body)) > maxBodySize {
        return fmt.Errorf("request body too large: exceeds %d bytes", maxBodySize)
    }

    // ... rest of code
}
```

### 3. Simple Auth Over HTTP (LOW-MEDIUM PRIORITY)

**Problem**: No warning or enforcement of HTTPS for simple auth mode
- Location: `auth.go:63-75`
- Impact: Secret transmitted in clear text
- Risk: Medium - Credential theft if used over HTTP

**Solution**: Add HTTPS validation option

```go
type AuthConfig struct {
    // ... existing fields
    RequireHTTPS bool // Enforce HTTPS for simple auth
}

func (c *AuthConfig) addSimpleAuth(req *http.Request) error {
    if c.Secret == "" {
        return fmt.Errorf("secret is required for simple authentication")
    }

    // Validate HTTPS if required
    if c.RequireHTTPS && req.URL.Scheme != "https" {
        return fmt.Errorf("simple authentication requires HTTPS (current: %s)", req.URL.Scheme)
    }

    // ... rest of code
}
```

## Medium Priority Improvements

### 4. Add Signature Version Support

**Rationale**: Allow algorithm upgrades without breaking existing clients

```go
const (
    SignatureVersionV1 = "v1" // Current: HMAC-SHA256
    SignatureVersionV2 = "v2" // Future: HMAC-SHA512 or other
)

type AuthConfig struct {
    // ... existing fields
    SignatureVersion string // Default to V1
}

func (c *AuthConfig) calculateHMACSignature(
    timestamp int64,
    method, path string,
    body []byte,
) string {
    version := c.SignatureVersion
    if version == "" {
        version = SignatureVersionV1
    }

    message := fmt.Sprintf("%s:%d%s%s%s",
        version, // Include version in message
        timestamp,
        method,
        path,
        string(body),
    )

    var h hash.Hash
    switch version {
    case SignatureVersionV2:
        h = hmac.New(sha512.New, []byte(c.Secret))
    default:
        h = hmac.New(sha256.New, []byte(c.Secret))
    }

    h.Write([]byte(message))
    return version + ":" + hex.EncodeToString(h.Sum(nil))
}
```

### 5. Add Request ID for Logging

```go
type AuthConfig struct {
    // ... existing fields
    RequestIDHeader string // Optional request ID header
}

// In VerifyHMACSignature, add:
requestID := req.Header.Get(c.RequestIDHeader)
if requestID == "" {
    requestID = "unknown"
}

// Use in error messages for correlation
return fmt.Errorf("[request_id=%s] signature verification failed", requestID)
```

## Low Priority Enhancements

### 6. Add Configurable Timestamp Tolerance

```go
type AuthConfig struct {
    // ... existing fields
    ClockSkewTolerance time.Duration // Allow client clock skew
}

func (c *AuthConfig) VerifyHMACSignature(req *http.Request, maxAge time.Duration) error {
    // ... parse timestamp

    tolerance := c.ClockSkewTolerance
    if tolerance == 0 {
        tolerance = 30 * time.Second // Default 30s
    }

    // Check timestamp with tolerance
    requestTime := time.Unix(timestamp, 0)
    now := time.Now()
    timeDiff := now.Sub(requestTime)

    if timeDiff > maxAge+tolerance {
        return fmt.Errorf("request timestamp expired")
    }

    if timeDiff < -(maxAge + tolerance) {
        return fmt.Errorf("request timestamp is too far in the future")
    }

    // ... rest
}
```

### 7. Add Rate Limiting Interface

```go
type RateLimiter interface {
    Allow(identifier string) bool
}

type AuthConfig struct {
    // ... existing fields
    RateLimiter RateLimiter
}

func (c *AuthConfig) VerifyHMACSignature(req *http.Request, maxAge time.Duration) error {
    // Rate limit by IP or signature
    if c.RateLimiter != nil {
        identifier := req.RemoteAddr // or signature
        if !c.RateLimiter.Allow(identifier) {
            return fmt.Errorf("rate limit exceeded")
        }
    }

    // ... rest of verification
}
```

## Additional Security Best Practices

### 8. Constant-Time String Comparison

Already implemented correctly ✅ (line 215: `hmac.Equal()`)

### 9. Secure Random for Nonce

Already using UUID v4 ✅ (line 85: `uuid.New()`) - cryptographically secure

### 10. Avoid Timing Attacks in Timestamp Check

Current implementation is safe - arithmetic operations don't leak info

## Testing Recommendations

Add tests for:
1. Nonce replay detection
2. Body size limit enforcement
3. HTTPS enforcement for simple auth
4. Concurrent nonce validation
5. Expired nonce cleanup
6. Version mismatch handling

## Performance Considerations

1. **Nonce Storage Cleanup**: Implement periodic cleanup to prevent memory growth
2. **Signature Calculation**: Already optimal - single pass over data
3. **Body Reading**: Already efficient with buffer reuse

## Comparison with Industry Standards

| Feature | Current | AWS Signature V4 | OAuth 2.0 HMAC |
|---------|---------|------------------|----------------|
| HMAC Algorithm | SHA256 ✅ | SHA256 ✅ | SHA1/SHA256 ✅ |
| Timestamp | ✅ | ✅ | ✅ |
| Nonce | ⚠️ Not validated | ✅ Used | ✅ Used |
| Body in Signature | ✅ | ✅ | ✅ |
| Query in Signature | ✅ | ✅ | ❌ |
| Headers in Signature | ❌ | ✅ | ⚠️ Partial |

## Migration Path

If implementing nonce validation on existing production systems:

1. **Phase 1**: Add nonce validation but in **log-only mode** (don't reject)
2. **Phase 2**: Monitor logs for duplicate nonces
3. **Phase 3**: Enable enforcement after ensuring all clients include unique nonces
4. **Phase 4**: Consider adding signature version for future changes

## Example: Complete Secure Configuration

```go
// Server-side setup
nonceStore := NewInMemoryNonceStore() // or NewRedisNonceStore(redisClient)

authConfig := &AuthConfig{
    Mode:               AuthModeHMAC,
    Secret:             os.Getenv("API_SECRET"),
    NonceStore:         nonceStore,
    RequireHTTPS:       true,
    SignatureVersion:   SignatureVersionV1,
    ClockSkewTolerance: 30 * time.Second,
}

// In HTTP handler
func authMiddleware(next http.Handler) http.Handler {
    return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
        maxAge := 5 * time.Minute
        maxBodySize := 10 * 1024 * 1024 // 10MB

        if err := authConfig.VerifyHMACSignature(r, maxAge, maxBodySize); err != nil {
            http.Error(w, "Authentication failed", http.StatusUnauthorized)
            log.Printf("Auth error: %v", err)
            return
        }

        next.ServeHTTP(w, r)
    })
}
```

## Conclusion

The current implementation is **good but not production-ready for high-security scenarios** without nonce validation. Priority order:

1. **Must-fix**: Nonce validation (prevents replay attacks)
2. **Should-fix**: Body size limit in verification (prevents DoS)
3. **Nice-to-have**: HTTPS enforcement, versioning, rate limiting

Implementing nonce validation alone would bring this from **B-grade to A-grade** security.
