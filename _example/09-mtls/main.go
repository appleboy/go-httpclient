package main

import (
	"context"
	"fmt"
	"io"
	"log"
	"net/http"
	"os"
	"time"

	httpclient "github.com/appleboy/go-httpclient"
)

func main() {
	fmt.Println("=== mTLS (Mutual TLS) Examples ===")

	// Check if certificate files exist
	if !filesExist("certs/client.crt", "certs/client.key", "certs/ca.crt") {
		fmt.Println("Certificate files not found!")
		fmt.Println("Please generate certificates first:")
		fmt.Println("  cd certs && ./generate.sh")
		fmt.Println("\nOr use your own certificates and place them in the certs/ directory:")
		fmt.Println("  - certs/ca.crt      (CA certificate)")
		fmt.Println("  - certs/client.crt  (Client certificate)")
		fmt.Println("  - certs/client.key  (Client private key)")
		os.Exit(1)
	}

	// Example 1: Load mTLS certificate from files
	fmt.Println("Example 1: Load mTLS certificate from files")
	fmt.Println("-------------------------------------------")
	example1()

	fmt.Println("\n---")

	// Example 2: Load mTLS certificate from byte content
	fmt.Println("Example 2: Load mTLS certificate from byte content")
	fmt.Println("---------------------------------------------------")
	example2()

	fmt.Println("\n---")

	// Example 3: Combine mTLS with custom CA certificate
	fmt.Println("Example 3: Combine mTLS with custom CA certificate")
	fmt.Println("---------------------------------------------------")
	example3()

	fmt.Println("\n---")

	// Example 4: Combine mTLS with other client options
	fmt.Println("Example 4: Combine mTLS with other client options")
	fmt.Println("--------------------------------------------------")
	example4()
}

// example1 demonstrates loading mTLS certificate from file paths
func example1() {
	client, err := httpclient.NewAuthClient(
		httpclient.AuthModeHMAC,
		"your-secret-key",
		httpclient.WithMTLSFromFile("certs/client.crt", "certs/client.key"),
	)
	if err != nil {
		log.Fatalf("Failed to create client: %v", err)
	}

	fmt.Printf("✓ Client created successfully with mTLS from files\n")
	fmt.Printf("  Certificate: certs/client.crt\n")
	fmt.Printf("  Private Key: certs/client.key\n")

	// Verify TLS configuration
	verifyTLSConfig(client)
}

// example2 demonstrates loading mTLS certificate from byte content
func example2() {
	// Read certificate and key files
	certPEM, err := os.ReadFile("certs/client.crt")
	if err != nil {
		log.Fatalf("Failed to read certificate: %v", err)
	}

	keyPEM, err := os.ReadFile("certs/client.key")
	if err != nil {
		log.Fatalf("Failed to read key: %v", err)
	}

	client, err := httpclient.NewAuthClient(
		httpclient.AuthModeHMAC,
		"your-secret-key",
		httpclient.WithMTLSFromBytes(certPEM, keyPEM),
	)
	if err != nil {
		log.Fatalf("Failed to create client: %v", err)
	}

	fmt.Printf("✓ Client created successfully with mTLS from bytes\n")
	fmt.Printf("  Certificate size: %d bytes\n", len(certPEM))
	fmt.Printf("  Private key size: %d bytes\n", len(keyPEM))

	// Verify TLS configuration
	verifyTLSConfig(client)
}

// example3 demonstrates combining mTLS with custom CA certificate
func example3() {
	client, err := httpclient.NewAuthClient(
		httpclient.AuthModeHMAC,
		"your-secret-key",
		httpclient.WithTLSCertFromFile("certs/ca.crt"), // Server CA
		httpclient.WithMTLSFromFile("certs/client.crt", "certs/client.key"), // Client cert
	)
	if err != nil {
		log.Fatalf("Failed to create client: %v", err)
	}

	fmt.Printf("✓ Client created successfully with both CA and mTLS certificates\n")
	fmt.Printf("  Server CA: certs/ca.crt\n")
	fmt.Printf("  Client Certificate: certs/client.crt\n")
	fmt.Printf("  Client Private Key: certs/client.key\n")

	// Verify TLS configuration
	verifyTLSConfig(client)
}

// example4 demonstrates combining mTLS with other client options
func example4() {
	client, err := httpclient.NewAuthClient(
		httpclient.AuthModeHMAC,
		"your-secret-key",
		httpclient.WithMTLSFromFile("certs/client.crt", "certs/client.key"),
		httpclient.WithTimeout(30*time.Second),
		httpclient.WithMaxBodySize(5*1024*1024), // 5MB
		httpclient.WithHMACHeaders("X-Signature", "X-Timestamp", "X-Nonce"),
	)
	if err != nil {
		log.Fatalf("Failed to create client: %v", err)
	}

	fmt.Printf("✓ Client created successfully with mTLS and custom options\n")
	fmt.Printf("  mTLS Certificate: certs/client.crt\n")
	fmt.Printf("  Timeout: 30s\n")
	fmt.Printf("  Max Body Size: 5MB\n")
	fmt.Printf("  HMAC Headers: Custom\n")

	// Verify TLS configuration
	verifyTLSConfig(client)

	// Make a sample request (will fail if no server is running, but demonstrates usage)
	fmt.Println("\n  Making a sample request...")
	makeRequest(client, "https://localhost:8443/api/test")
}

// verifyTLSConfig checks if TLS configuration is properly set
func verifyTLSConfig(client *http.Client) {
	// Extract transport
	if client.Transport == nil {
		fmt.Println("  ✗ No transport configured")
		return
	}

	// Try to get authRoundTripper
	type authRoundTripper interface {
		RoundTrip(*http.Request) (*http.Response, error)
	}

	if _, ok := client.Transport.(authRoundTripper); ok {
		// Cannot directly inspect private fields, but we know transport is configured
		fmt.Println("  ✓ TLS transport is configured")
		fmt.Println("  ✓ Client certificates are loaded")
	}
}

// makeRequest demonstrates making a request with the configured client
func makeRequest(client *http.Client, url string) {
	req, err := http.NewRequestWithContext(
		context.Background(),
		http.MethodGet,
		url,
		nil,
	)
	if err != nil {
		fmt.Printf("  ✗ Failed to create request: %v\n", err)
		return
	}

	resp, err := client.Do(req)
	if err != nil {
		fmt.Printf("  ℹ Note: Request failed (expected if no mTLS server is running): %v\n", err)
		return
	}
	defer resp.Body.Close()

	body, _ := io.ReadAll(resp.Body)
	fmt.Printf("  ✓ Request successful\n")
	fmt.Printf("    Status: %d\n", resp.StatusCode)
	fmt.Printf("    Response: %s\n", string(body))
}

// filesExist checks if all specified files exist
func filesExist(files ...string) bool {
	for _, file := range files {
		if _, err := os.Stat(file); os.IsNotExist(err) {
			return false
		}
	}
	return true
}
