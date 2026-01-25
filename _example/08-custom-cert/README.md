# Custom TLS Certificate Examples

This example demonstrates how to use custom TLS certificates with the HTTP client. This is useful in enterprise environments where you need to trust custom Certificate Authorities (CA) or self-signed certificates.

## Features

The `go-httpclient` package supports loading custom TLS certificates from three sources:

1. **From File Path** - Load certificate from a local file
2. **From URL** - Download certificate from a URL
3. **From Bytes** - Load certificate from byte content (embedded or external source)

## Security

- All custom certificates are added to the system certificate pool (not replacing it)
- TLS 1.2 is enforced as the minimum version
- Multiple certificates can be loaded for certificate chain verification
- Invalid certificates are silently skipped to maintain compatibility

## Usage Examples

### 1. Load Certificate from File

```go
client := httpclient.NewAuthClient(
    httpclient.AuthModeHMAC,
    "your-secret-key",
    httpclient.WithTLSCertFromFile("/etc/ssl/certs/company-ca.crt"),
)
```

### 2. Load Certificate from URL

```go
client := httpclient.NewAuthClient(
    httpclient.AuthModeHMAC,
    "your-secret-key",
    httpclient.WithTLSCertFromURL("https://internal-ca.company.com/ca.crt"),
)
```

### 3. Load Certificate from Bytes

```go
certPEM := []byte(`-----BEGIN CERTIFICATE-----
MIIDXTCCAkWgAwIBAgIJAKL0UG+mRKmdMA0GCSqGSIb3DQEBCwUAMEUxCzAJBgNV
... (certificate content) ...
-----END CERTIFICATE-----`)

client := httpclient.NewAuthClient(
    httpclient.AuthModeHMAC,
    "your-secret-key",
    httpclient.WithTLSCertFromBytes(certPEM),
)
```

### 4. Load Multiple Certificates

```go
client := httpclient.NewAuthClient(
    httpclient.AuthModeHMAC,
    "your-secret-key",
    httpclient.WithTLSCertFromFile("/etc/ssl/certs/root-ca.crt"),
    httpclient.WithTLSCertFromFile("/etc/ssl/certs/intermediate-ca.crt"),
)
```

### 5. Combine with Other Options

```go
client := httpclient.NewAuthClient(
    httpclient.AuthModeHMAC,
    "your-secret-key",
    httpclient.WithTLSCertFromFile("/etc/ssl/certs/company-ca.crt"),
    httpclient.WithTimeout(30*time.Second),
    httpclient.WithMaxBodySize(5*1024*1024),
)
```

### 6. Use with Custom Transport

```go
customTransport := &http.Transport{
    MaxIdleConns:        100,
    MaxIdleConnsPerHost: 10,
}

client := httpclient.NewAuthClient(
    httpclient.AuthModeHMAC,
    "your-secret-key",
    httpclient.WithTransport(customTransport),
    httpclient.WithTLSCertFromFile("/etc/ssl/certs/company-ca.crt"),
)
```

When using `WithTransport` with certificate options, the package will:

- Clone the provided transport if it's an `*http.Transport`
- Apply the TLS configuration to the cloned transport
- Use the original transport if it cannot be safely modified

## Certificate Format

Certificates must be in PEM format:

```txt
-----BEGIN CERTIFICATE-----
MIIDXTCCAkWgAwIBAgIJAKL0UG+mRKmdMA0GCSqGSIb3DQEBCwUAMEUxCzAJBgNV
... (base64 encoded certificate data) ...
-----END CERTIFICATE-----
```

## Common Use Cases

### Enterprise Internal APIs

```go
// Connect to internal API with company CA
client := httpclient.NewAuthClient(
    httpclient.AuthModeHMAC,
    os.Getenv("API_SECRET"),
    httpclient.WithTLSCertFromFile("/etc/ssl/certs/company-ca.crt"),
)

resp, err := client.Get("https://api.internal.company.com/data")
```

### Development with Self-Signed Certificates

```go
// For development/testing environments
client := httpclient.NewAuthClient(
    httpclient.AuthModeSimple,
    "dev-secret",
    httpclient.WithTLSCertFromFile("./dev-certs/self-signed.crt"),
)
```

### Certificate Chain Verification

```go
// Load complete certificate chain
client := httpclient.NewAuthClient(
    httpclient.AuthModeHMAC,
    "secret",
    httpclient.WithTLSCertFromFile("/etc/ssl/certs/root-ca.crt"),
    httpclient.WithTLSCertFromFile("/etc/ssl/certs/intermediate-ca.crt"),
    httpclient.WithTLSCertFromFile("/etc/ssl/certs/server-ca.crt"),
)
```

## Error Handling

Certificate loading errors are handled gracefully:

- If a file cannot be read, it's silently skipped
- If a URL cannot be fetched, it's silently skipped
- If certificate data is invalid, it's silently skipped
- The client will still be created and use system certificates

To verify certificate loading, test your connection to the target server.

## Running the Example

```bash
# Make sure you have the required certificate file
# Or modify the example to use your own certificate

go run main.go
```

## Notes

- Certificates are loaded when `NewAuthClient()` is called
- The system certificate pool is preserved (custom certs are added to it)
- Multiple certificates can be loaded for certificate chain verification
- TLS 1.2 is enforced as the minimum version for security
