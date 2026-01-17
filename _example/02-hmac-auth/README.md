# HMAC Signature Authentication Example

This example demonstrates how to use HMAC-SHA256 signature authentication for secure API communication.

## Features

- Cryptographic signature using HMAC-SHA256
- Timestamp-based replay attack prevention
- Nonce for request uniqueness
- Query parameters included in signature
- No secret transmitted over network

## Usage

```bash
go run main.go
```

## How It Works

1. Create `AuthConfig` with `AuthModeHMAC` and your shared secret
2. Call `AddAuthHeaders()` with request and body
3. Three headers are added automatically:
   - `X-Signature`: HMAC-SHA256 signature
   - `X-Timestamp`: Unix timestamp
   - `X-Nonce`: Unique request identifier (UUID)

## Signature Calculation

```
message = timestamp + method + path + query + body
signature = HMAC-SHA256(secret, message)
```

**Example:**
- Timestamp: `1704067200`
- Method: `POST`
- Path: `/v1/resources?type=user&role=admin`
- Body: `{"action":"create","resource":"user"}`
- Message: `1704067200POST/v1/resources?type=user&role=admin{"action":"create","resource":"user"}`

## Example Output

```
Request Details:
  Method: POST
  URL: https://api.example.com/v1/resources?type=user&role=admin
  Body: {"action": "create", "resource": "user"}

Authentication Headers:
  X-Signature: a1b2c3d4e5f6...
  X-Timestamp: 1704067200
  X-Nonce: 550e8400-e29b-41d4-a716-446655440000

HMAC authentication headers added successfully!
```

## Security Benefits

- **Tamper-proof**: Any modification to request invalidates signature
- **Replay protection**: Old signatures are rejected based on timestamp
- **No secret exposure**: Secret never transmitted, only signature
- **Query parameter security**: Parameters cannot be added/modified without detection

## Server-Side Verification

See `04-server-verification` example for how to verify these signatures on the server side.
