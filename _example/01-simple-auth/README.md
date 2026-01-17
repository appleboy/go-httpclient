# Simple API Key Authentication Example

This example demonstrates how to use simple API key authentication mode.

## Features

- Simple API secret transmitted in HTTP header
- Default header name: `X-API-Secret`
- Suitable for internal APIs or trusted networks
- Easy to implement and use

## Usage

```bash
go run main.go
```

## How It Works

1. Create `AuthConfig` with `AuthModeSimple` and your secret key
2. Call `AddAuthHeaders()` to add the authentication header
3. The secret is sent in the `X-API-Secret` header

## Example Output

```
Request Headers:
  Content-Type: application/json
  X-API-Secret: my-secret-api-key

Simple authentication header added successfully!
The X-API-Secret header contains the API key for authentication.
```

## Security Note

Simple mode transmits the secret directly in headers. Always use HTTPS in production to prevent secret exposure.
