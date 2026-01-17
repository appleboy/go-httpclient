package main

import (
	"bytes"
	"context"
	"fmt"
	"httpclient"
	"net/http"
	"strings"
	"time"
)

func main() {
	fmt.Println("=== RoundTripper-based HTTP Client Example ===\n")

	// One-line client creation with all configurations!
	client := httpclient.NewAuthClient(
		httpclient.AuthModeHMAC, // Authentication mode
		"my-shared-secret",      // Shared secret
		httpclient.WithTimeout(10*time.Second),
		httpclient.WithMaxBodySize(5*1024*1024), // 5MB limit
		httpclient.WithSkipAuthFunc(func(req *http.Request) bool {
			// Skip authentication for health check endpoints
			return strings.HasPrefix(req.URL.Path, "/health")
		}),
	)

	// Example 1: POST request with JSON body
	fmt.Println("Example 1: POST with JSON body")
	body := []byte(`{"username": "john", "action": "login"}`)
	fmt.Printf("  Request Body: %s\n", string(body))

	// Note: This would actually make a request to the URL
	// For demonstration, we're just showing the setup
	fmt.Println("  Would send POST to: https://api.example.com/auth?version=v1")
	fmt.Println("  Content-Type: application/json")
	fmt.Println("  ✓ Authentication headers automatically added!")

	// In real usage:
	// resp, err := client.Post(
	//     "https://api.example.com/auth?version=v1",
	//     "application/json",
	//     bytes.NewReader(body),
	// )

	// Example 2: GET request (no body)
	fmt.Println("\nExample 2: GET request")
	fmt.Println("  Would send GET to: https://api.example.com/users/123")
	fmt.Println("  ✓ Authentication headers automatically added!")

	// In real usage:
	// resp, err := client.Get("https://api.example.com/users/123")

	// Example 3: Custom request with context
	fmt.Println("\nExample 3: Custom request with context")
	ctx := context.Background()
	req, _ := http.NewRequestWithContext(
		ctx,
		http.MethodPut,
		"https://api.example.com/users/123",
		bytes.NewReader([]byte(`{"name": "Jane"}`)),
	)
	req.Header.Set("Content-Type", "application/json")

	fmt.Printf("  Method: %s\n", req.Method)
	fmt.Printf("  URL: %s\n", req.URL.String())
	fmt.Println("  ✓ Authentication headers automatically added!")

	// In real usage:
	// resp, err := client.Do(req)

	// Example 4: Health check (no authentication)
	fmt.Println("\nExample 4: Health check (no auth)")
	fmt.Println("  Would send GET to: https://api.example.com/health")
	fmt.Println("  ✓ Authentication skipped for /health endpoint!")

	// In real usage:
	// resp, err := client.Get("https://api.example.com/health")

	// Summary
	fmt.Println("\n=== Summary ===")
	fmt.Println("✓ All requests automatically signed with HMAC-SHA256!")
	fmt.Println("✓ No manual AddAuthHeaders() calls needed!")
	fmt.Println("✓ Body handling is automatic!")
	fmt.Println("✓ Health checks skip authentication!")
	fmt.Println("✓ Configurable timeout and body size limits!")

	// Comparison with old approach
	fmt.Println("\n=== Code Comparison ===")
	fmt.Println("\nOld approach (6 lines):")
	fmt.Println("  config := httpclient.NewAuthConfig(httpclient.AuthModeHMAC, \"secret\")")
	fmt.Println("  body := []byte(`{\"data\": \"value\"}`)")
	fmt.Println("  req, _ := http.NewRequest(\"POST\", url, bytes.NewReader(body))")
	fmt.Println("  config.AddAuthHeaders(req, body)")
	fmt.Println("  client := &http.Client{}")
	fmt.Println("  resp, err := client.Do(req)")

	fmt.Println("\nNew approach (2 lines):")
	fmt.Println("  client := httpclient.NewAuthClient(httpclient.AuthModeHMAC, \"secret\")")
	fmt.Println("  resp, err := client.Post(url, \"application/json\", bytes.NewReader(body))")

	fmt.Println("\n67% less code! 🎉")
}
