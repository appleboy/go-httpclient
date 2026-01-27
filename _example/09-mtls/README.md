# mTLS (Mutual TLS) Example

This example demonstrates how to use client-side certificates for mutual TLS (mTLS) authentication with the `go-httpclient` package.

## What is mTLS?

Mutual TLS (mTLS) is a security protocol that provides **two-way authentication** between client and server:

- **Traditional TLS**: Only the server proves its identity to the client
- **mTLS**: Both the client AND server prove their identities to each other

This is commonly used in:

- Service-to-service communication
- Zero-trust network architectures
- API security in enterprise environments
- Banking and financial systems
- Government and healthcare systems

## Features Demonstrated

This example shows how to:

1. **Load mTLS certificates from files** (`WithMTLSFromFile`)
2. **Load mTLS certificates from byte content** (`WithMTLSFromBytes`)
3. **Combine mTLS with custom CA certificates** (for self-signed or internal CAs)
4. **Combine mTLS with other client options** (timeouts, body size limits, custom headers)

## Prerequisites

You need three files for mTLS:

1. **Client Certificate** (`client.crt`) - Proves the client's identity
2. **Client Private Key** (`client.key`) - Paired with the certificate
3. **CA Certificate** (`ca.crt`) - Verifies the server's certificate (optional, for custom CAs)

### Generating Test Certificates

Use the provided script to generate self-signed certificates for testing:

```bash
cd certs
./generate.sh
```

This will create:

- `ca.crt` and `ca.key` - Certificate Authority
- `server.crt` and `server.key` - Server certificate
- `client.crt` and `client.key` - Client certificate

**Note**: These are self-signed certificates for **testing only**. In production, use certificates from a trusted CA.

### Using Your Own Certificates

If you have your own certificates, place them in the `certs/` directory:

```txt
_example/09-mtls/certs/
├── ca.crt           # CA certificate (optional)
├── client.crt       # Your client certificate
└── client.key       # Your client private key
```

## Running the Example

```bash
# Generate test certificates first (if not already done)
cd certs && ./generate.sh && cd ..

# Run the example
go run main.go
```

## Code Examples

### Example 1: Load from Files

The simplest way to use mTLS:

```go
client, err := httpclient.NewAuthClient(
    httpclient.AuthModeHMAC,
    "your-secret-key",
    httpclient.WithMTLSFromFile("certs/client.crt", "certs/client.key"),
)
if err != nil {
    log.Fatal(err)
}
```

### Example 2: Load from Bytes

Useful when certificates are embedded or loaded from a secret management system:

```go
certPEM, _ := os.ReadFile("certs/client.crt")
keyPEM, _ := os.ReadFile("certs/client.key")

client, err := httpclient.NewAuthClient(
    httpclient.AuthModeHMAC,
    "your-secret-key",
    httpclient.WithMTLSFromBytes(certPEM, keyPEM),
)
if err != nil {
    log.Fatal(err)
}
```

### Example 3: With Custom CA

When connecting to servers with self-signed or internal CA certificates:

```go
client, err := httpclient.NewAuthClient(
    httpclient.AuthModeHMAC,
    "your-secret-key",
    httpclient.WithTLSCertFromFile("certs/ca.crt"),              // Trust server's CA
    httpclient.WithMTLSFromFile("certs/client.crt", "certs/client.key"), // Client cert
)
if err != nil {
    log.Fatal(err)
}
```

### Example 4: With Other Options

Combine mTLS with other client configuration:

```go
client, err := httpclient.NewAuthClient(
    httpclient.AuthModeHMAC,
    "your-secret-key",
    httpclient.WithMTLSFromFile("certs/client.crt", "certs/client.key"),
    httpclient.WithTimeout(30*time.Second),
    httpclient.WithMaxBodySize(5*1024*1024),
    httpclient.WithHMACHeaders("X-Signature", "X-Timestamp", "X-Nonce"),
)
if err != nil {
    log.Fatal(err)
}
```

## Error Handling

The `NewAuthClient` function returns an error if:

- Certificate file not found
- Private key file not found
- Certificate and key don't match
- Certificate or key is invalid or corrupted

```go
client, err := httpclient.NewAuthClient(
    httpclient.AuthModeHMAC,
    "secret",
    httpclient.WithMTLSFromFile("client.crt", "client.key"),
)
if err != nil {
    if os.IsNotExist(err) {
        log.Fatal("Certificate file not found")
    }
    log.Fatalf("Failed to create client: %v", err)
}
```

## Testing with a mTLS Server

To test the client, you need a server that requires client certificates. Here's a simple test server:

```go
package main

import (
    "crypto/tls"
    "crypto/x509"
    "fmt"
    "log"
    "net/http"
    "os"
)

func main() {
    // Load CA certificate to verify client certificates
    caCert, err := os.ReadFile("certs/ca.crt")
    if err != nil {
        log.Fatal(err)
    }

    caCertPool := x509.NewCertPool()
    caCertPool.AppendCertsFromPEM(caCert)

    // Configure TLS
    tlsConfig := &tls.Config{
        ClientAuth: tls.RequireAndVerifyClientCert,
        ClientCAs:  caCertPool,
        MinVersion: tls.VersionTLS12,
    }

    // Create server
    server := &http.Server{
        Addr:      ":8443",
        TLSConfig: tlsConfig,
    }

    http.HandleFunc("/", func(w http.ResponseWriter, r *http.Request) {
        // Verify client certificate
        if r.TLS == nil || len(r.TLS.PeerCertificates) == 0 {
            http.Error(w, "No client certificate", http.StatusUnauthorized)
            return
        }

        clientCert := r.TLS.PeerCertificates[0]
        fmt.Fprintf(w, "Hello %s!\n", clientCert.Subject.CommonName)
    })

    log.Println("Starting mTLS server on :8443")
    log.Fatal(server.ListenAndServeTLS("certs/server.crt", "certs/server.key"))
}
```

## Production Considerations

1. **Certificate Management**:
   - Use a proper CA (Let's Encrypt, internal PKI, etc.)
   - Implement certificate rotation
   - Monitor certificate expiration

2. **Security**:
   - Store private keys securely (never in source control)
   - Use appropriate file permissions (0600 for private keys)
   - Consider using a key management service (AWS KMS, HashiCorp Vault, etc.)

3. **Error Handling**:
   - Always check errors from `NewAuthClient`
   - Log certificate-related errors for debugging
   - Implement retry logic with exponential backoff

4. **Testing**:
   - Test with expired certificates
   - Test with mismatched certificate pairs
   - Test certificate revocation scenarios

## Troubleshooting

### "certificate signed by unknown authority"

The server's certificate is not trusted. Solutions:

- Add server's CA certificate with `WithTLSCertFromFile`
- Use a certificate from a trusted CA

### "tls: bad certificate"

The server rejected your client certificate. Check:

- Client certificate is signed by a CA the server trusts
- Client certificate has not expired
- Certificate and key match

### "failed to read mTLS cert from..."

File not found or permission denied. Check:

- File path is correct
- File exists
- You have read permissions

### "invalid mTLS cert/key pair"

Certificate and key don't match. Verify:

- Certificate and key are a valid pair
- Files are in correct PEM format
- Files are not corrupted

## Related Examples

- [Custom TLS Certificates](../08-custom-cert/) - Using custom CA certificates
- [Options Showcase](../06-options-showcase/) - All available client options
- [HMAC Authentication](../02-hmac-auth/) - Using HMAC authentication mode

## References

- [RFC 8446 - TLS 1.3](https://datatracker.ietf.org/doc/html/rfc8446)
- [mTLS Best Practices](https://www.cloudflare.com/learning/access-management/what-is-mutual-tls/)
- [Go crypto/tls Documentation](https://pkg.go.dev/crypto/tls)
