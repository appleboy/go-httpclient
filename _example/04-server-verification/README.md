# Server-Side Verification Example

This example demonstrates how to verify HMAC signatures on the server side to authenticate incoming requests.

## Features

- Complete HTTP server with authentication middleware
- HMAC signature verification
- Timestamp validation (replay attack prevention)
- Automatic request body preservation
- Comprehensive error handling

## Usage

```bash
go run main.go
```

The server will start on `http://localhost:8080` and automatically run test cases.

## How It Works

### 1. Authentication Middleware

```go
func authMiddleware(next http.HandlerFunc) http.HandlerFunc {
    return func(w http.ResponseWriter, r *http.Request) {
        auth := httpclient.NewAuthConfig(httpclient.AuthModeHMAC, "shared-secret-key")

        // Verify HMAC signature (max age: 5 minutes)
        if err := auth.VerifyHMACSignature(r, 5*time.Minute); err != nil {
            http.Error(w, "Authentication failed", http.StatusUnauthorized)
            return
        }

        next(w, r)
    }
}
```

### 2. Protected Handler

```go
http.HandleFunc("/api/data", authMiddleware(dataHandler))
```

## Verification Process

1. **Extract Headers**: Read signature, timestamp, and nonce from request headers
2. **Validate Timestamp**: Check if request is not too old or too far in future
3. **Read Body**: Read request body for signature calculation
4. **Calculate Signature**: Compute expected signature using same algorithm as client
5. **Compare Signatures**: Use constant-time comparison to prevent timing attacks
6. **Restore Body**: Put body back into request for downstream handlers

## Test Cases

The example runs four test cases automatically:

### Test 1: Valid HMAC Request ✅
- Properly signed request with valid timestamp
- Expected: `200 OK` with success message

### Test 2: Invalid Signature ❌
- Request with incorrect signature
- Expected: `401 Unauthorized` with "signature verification failed"

### Test 3: Expired Timestamp ❌
- Request with 10-minute-old timestamp (exceeds 5-minute limit)
- Expected: `401 Unauthorized` with "request timestamp expired"

### Test 4: Missing Headers ❌
- Request without authentication headers
- Expected: `401 Unauthorized` with "missing authentication headers"

## Example Output

```
Server starting on http://localhost:8080
Testing with sample requests...

=== Test 1: Valid HMAC Request ===
  ✅ Authentication successful
  📦 Received: {"action": "read", "resource": "data"}
  📨 Response (200): {"status": "success", "message": "Data received"}

=== Test 2: Invalid Signature ===
  ❌ Authentication failed: signature verification failed
  📨 Response (401): Authentication failed: signature verification failed

=== Test 3: Expired Timestamp ===
  ❌ Authentication failed: request timestamp expired
  📨 Response (401): Authentication failed: request timestamp expired

=== Test 4: Missing Headers ===
  ❌ Authentication failed: missing authentication headers
  📨 Response (401): Authentication failed: missing authentication headers
```

## Security Features

- **Replay Attack Prevention**: Timestamp must be within acceptable time window (default: 5 minutes)
- **Constant-Time Comparison**: Uses `hmac.Equal()` to prevent timing attacks
- **Body Preservation**: Body is read once and restored for handlers
- **Future Timestamp Rejection**: Prevents clock skew attacks
- **Query Parameter Protection**: Query parameters are included in signature

## Configuration

### Adjust Timestamp Tolerance

```go
// Allow 10-minute window instead of default 5 minutes
auth.VerifyHMACSignature(r, 10*time.Minute)
```

### Custom Headers

```go
auth := httpclient.NewAuthConfig(httpclient.AuthModeHMAC, "secret")
auth.SignatureHeader = "X-Custom-Signature"
auth.TimestampHeader = "X-Custom-Timestamp"
auth.NonceHeader = "X-Custom-Nonce"
```

## Integration Example

### Gin Framework

```go
func AuthMiddleware() gin.HandlerFunc {
    return func(c *gin.Context) {
        auth := httpclient.NewAuthConfig(httpclient.AuthModeHMAC, "secret")
        if err := auth.VerifyHMACSignature(c.Request, 5*time.Minute); err != nil {
            c.JSON(401, gin.H{"error": "Authentication failed"})
            c.Abort()
            return
        }
        c.Next()
    }
}

router.POST("/api/data", AuthMiddleware(), dataHandler)
```

### Echo Framework

```go
func AuthMiddleware(next echo.HandlerFunc) echo.HandlerFunc {
    return func(c echo.Context) error {
        auth := httpclient.NewAuthConfig(httpclient.AuthModeHMAC, "secret")
        if err := auth.VerifyHMACSignature(c.Request(), 5*time.Minute); err != nil {
            return echo.NewHTTPError(401, "Authentication failed")
        }
        return next(c)
    }
}

e.POST("/api/data", dataHandler, AuthMiddleware)
```

## Important Notes

- Client and server must use the **same secret key**
- Client and server must use the **same custom header names** (if customized)
- Timestamp tolerance should balance security and clock skew
- Always use HTTPS in production to prevent header tampering
