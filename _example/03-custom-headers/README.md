# Custom Header Names Example

This example demonstrates how to customize HTTP header names for authentication.

## Features

- Customize simple auth header name
- Customize HMAC signature header names
- Maintain compatibility with existing APIs
- Support for legacy systems with specific header requirements

## Usage

```bash
go run main.go
```

## Customizable Headers

### Simple Mode

| Default         | Customizable Property | Example Value     |
| --------------- | --------------------- | ----------------- |
| `X-API-Secret`  | `HeaderName`          | `Authorization`   |

### HMAC Mode

| Default         | Customizable Property | Example Value          |
| --------------- | --------------------- | ---------------------- |
| `X-Signature`   | `SignatureHeader`     | `X-Request-Signature`  |
| `X-Timestamp`   | `TimestampHeader`     | `X-Request-Time`       |
| `X-Nonce`       | `NonceHeader`         | `X-Request-ID`         |

## Example Code

### Simple Auth with Custom Header

```go
auth := httpclient.NewAuthConfig(httpclient.AuthModeSimple, "my-api-key")
auth.HeaderName = "Authorization" // Custom header name
auth.AddAuthHeaders(req, nil)
```

### HMAC Auth with Custom Headers

```go
auth := httpclient.NewAuthConfig(httpclient.AuthModeHMAC, "shared-secret")
auth.SignatureHeader = "X-Request-Signature"
auth.TimestampHeader = "X-Request-Time"
auth.NonceHeader = "X-Request-ID"
auth.AddAuthHeaders(req, reqBody)
```

## Use Cases

- **API Gateway Integration**: Match existing header naming conventions
- **Legacy System Support**: Work with systems expecting specific header names
- **Corporate Standards**: Comply with organization-wide naming policies
- **Multi-tenant APIs**: Different header names for different clients

## Example Output

```
=== Example 1: Custom Simple Auth Header ===

Request Headers:
  Authorization: my-api-key

Note: Using 'Authorization' instead of default 'X-API-Secret'


=== Example 2: Custom HMAC Headers ===

Request Headers:
  X-Request-Signature: a1b2c3d4e5f6...
  X-Request-Time: 1704067200
  X-Request-ID: 550e8400-e29b-41d4-a716-446655440000

Custom Header Mappings:
  Default           → Custom
  X-Signature       → X-Request-Signature
  X-Timestamp       → X-Request-Time
  X-Nonce           → X-Request-ID
```

## Important Notes

- Both client and server must use the same custom header names
- Custom headers must be configured identically on both sides
- Default header names are used if custom names are not specified
