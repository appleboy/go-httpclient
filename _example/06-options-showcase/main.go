package main

import (
	"fmt"
	"log"
	"net/http"
	"strings"
	"time"

	"github.com/appleboy/go-httpclient"
)

func main() {
	// Example 1: Minimal setup (only required parameters)
	fmt.Println("Example 1: Minimal setup")
	client1, err := httpclient.NewAuthClient(
		httpclient.AuthModeSimple,
		"my-api-key",
	)
	if err != nil {
		log.Fatalf("Failed to create client: %v", err)
	}
	fmt.Println("✓ Client created with default settings")
	fmt.Println("  - Timeout: 30s (default)")
	fmt.Println("  - Max Body Size: 10MB (default)")
	fmt.Println("  - Header: X-API-Secret (default)")
	_ = client1

	// Example 2: Custom timeout
	fmt.Println("\nExample 2: Custom timeout")
	client2, err := httpclient.NewAuthClient(
		httpclient.AuthModeHMAC,
		"secret",
		httpclient.WithTimeout(5*time.Second),
	)
	if err != nil {
		log.Fatalf("Failed to create client: %v", err)
	}
	fmt.Println("✓ Client created with 5s timeout")
	_ = client2

	// Example 3: Body size limit
	fmt.Println("\nExample 3: Body size limit")
	client3, err := httpclient.NewAuthClient(
		httpclient.AuthModeHMAC,
		"secret",
		httpclient.WithMaxBodySize(1024*1024), // 1MB
	)
	if err != nil {
		log.Fatalf("Failed to create client: %v", err)
	}
	fmt.Println("✓ Client created with 1MB body limit")
	fmt.Println("  (prevents memory exhaustion with large uploads)")
	_ = client3

	// Example 4: Custom HMAC headers
	fmt.Println("\nExample 4: Custom HMAC headers")
	client4, err := httpclient.NewAuthClient(
		httpclient.AuthModeHMAC,
		"secret",
		httpclient.WithHMACHeaders("X-Sig", "X-Time", "X-ID"),
	)
	if err != nil {
		log.Fatalf("Failed to create client: %v", err)
	}
	fmt.Println("✓ Client created with custom header names:")
	fmt.Println("  - Signature: X-Sig (instead of X-Signature)")
	fmt.Println("  - Timestamp: X-Time (instead of X-Timestamp)")
	fmt.Println("  - Nonce: X-ID (instead of X-Nonce)")
	_ = client4

	// Example 5: Custom simple mode header
	fmt.Println("\nExample 5: Custom simple mode header")
	client5, err := httpclient.NewAuthClient(
		httpclient.AuthModeSimple,
		"my-api-key",
		httpclient.WithHeaderName("Authorization"),
	)
	if err != nil {
		log.Fatalf("Failed to create client: %v", err)
	}
	fmt.Println("✓ Client created with custom header name:")
	fmt.Println("  - Header: Authorization (instead of X-API-Secret)")
	_ = client5

	// Example 6: Skip auth for certain endpoints
	fmt.Println("\nExample 6: Skip auth for certain endpoints")
	client6, err := httpclient.NewAuthClient(
		httpclient.AuthModeHMAC,
		"secret",
		httpclient.WithSkipAuthFunc(func(req *http.Request) bool {
			// Skip auth for /health and /metrics endpoints
			path := req.URL.Path
			return strings.HasPrefix(path, "/health") ||
				strings.HasPrefix(path, "/metrics")
		}),
	)
	if err != nil {
		log.Fatalf("Failed to create client: %v", err)
	}
	fmt.Println("✓ Client created with skip auth function")
	fmt.Println("  - /health → No authentication")
	fmt.Println("  - /metrics → No authentication")
	fmt.Println("  - /api/* → Authentication required")
	_ = client6

	// Example 7: Custom transport
	fmt.Println("\nExample 7: Custom transport")
	customTransport := &http.Transport{
		MaxIdleConns:        100,
		MaxIdleConnsPerHost: 10,
		IdleConnTimeout:     90 * time.Second,
	}
	client7, err := httpclient.NewAuthClient(
		httpclient.AuthModeHMAC,
		"secret",
		httpclient.WithTransport(customTransport),
	)
	if err != nil {
		log.Fatalf("Failed to create client: %v", err)
	}
	fmt.Println("✓ Client created with custom transport")
	fmt.Println("  - MaxIdleConns: 100")
	fmt.Println("  - MaxIdleConnsPerHost: 10")
	fmt.Println("  - IdleConnTimeout: 90s")
	_ = client7

	// Example 8: Combining all options
	fmt.Println("\nExample 8: All options combined")
	client8, err := httpclient.NewAuthClient(
		httpclient.AuthModeHMAC,
		"secret",
		httpclient.WithTimeout(10*time.Second),
		httpclient.WithMaxBodySize(5*1024*1024),
		httpclient.WithTransport(customTransport),
		httpclient.WithHMACHeaders("X-Signature", "X-Timestamp", "X-Nonce"),
		httpclient.WithSkipAuthFunc(func(req *http.Request) bool {
			return strings.HasPrefix(req.URL.Path, "/public")
		}),
	)
	if err != nil {
		log.Fatalf("Failed to create client: %v", err)
	}
	fmt.Println("✓ Client created with all options combined:")
	fmt.Println("  - Timeout: 10s")
	fmt.Println("  - Max Body Size: 5MB")
	fmt.Println("  - Custom transport")
	fmt.Println("  - Custom headers")
	fmt.Println("  - Skip auth for /public/*")
	_ = client8

	// Summary
	fmt.Println("\n=== Summary ===")
	fmt.Println("✓ Option Pattern provides flexible configuration")
	fmt.Println("✓ All options have sensible defaults")
	fmt.Println("✓ Options can be combined in any order")
	fmt.Println("✓ Easy to add new options in the future")

	fmt.Println("\n=== Available Options ===")
	fmt.Println("Authentication options:")
	fmt.Println("  - WithHeaderName(name) - Custom header for simple mode")
	fmt.Println("  - WithHMACHeaders(sig, ts, nonce) - Custom headers for HMAC mode")

	fmt.Println("\nClient behavior options:")
	fmt.Println("  - WithTransport(transport) - Custom HTTP transport")
	fmt.Println("  - WithTimeout(duration) - Request timeout")
	fmt.Println("  - WithMaxBodySize(bytes) - Maximum request body size")
	fmt.Println("  - WithSkipAuthFunc(func) - Conditionally skip authentication")

	fmt.Println("\n=== All examples completed! ===")
}
