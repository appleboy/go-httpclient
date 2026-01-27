package main

import (
	"bytes"
	"fmt"
	"log"
	"net/http"

	"github.com/appleboy/go-httpclient"
)

func main() {
	// Create HTTP client with HMAC authentication mode
	// Authentication headers are added automatically to all requests
	client, err := httpclient.NewAuthClient(httpclient.AuthModeHMAC, "my-shared-secret")
	if err != nil {
		log.Fatalf("Failed to create client: %v", err)
	}

	// Create HTTP request with query parameters
	reqBody := []byte(`{"action": "create", "resource": "user"}`)
	req, err := http.NewRequest(
		http.MethodPost,
		"https://api.example.com/v1/resources?type=user&role=admin",
		bytes.NewBuffer(reqBody),
	)
	if err != nil {
		log.Fatalf("Failed to create request: %v", err)
	}

	// Set content type
	req.Header.Set("Content-Type", "application/json")

	fmt.Println("Request Details:")
	fmt.Printf("  Method: %s\n", req.Method)
	fmt.Printf("  URL: %s\n", req.URL.String())
	fmt.Printf("  Body: %s\n", string(reqBody))

	fmt.Println("\nMaking request with automatic HMAC authentication...")
	fmt.Println("The following headers will be added automatically:")
	fmt.Println("  - X-Signature: HMAC-SHA256 signature")
	fmt.Println("  - X-Timestamp: Unix timestamp")
	fmt.Println("  - X-Nonce: Unique request identifier")

	// Send request (commented out to avoid actual HTTP call)
	// The client automatically adds authentication headers before sending
	// resp, err := client.Do(req)
	// if err != nil {
	// 	log.Fatalf("Request failed: %v", err)
	// }
	// defer resp.Body.Close()

	fmt.Println("\nClient configured successfully!")

	// Silence "declared and not used" error for demonstration
	_ = client
	_ = req

	fmt.Println("\nSignature Calculation:")
	fmt.Println("  message = timestamp + method + path + query + body")
	fmt.Println("  signature = HMAC-SHA256(secret, message)")
	fmt.Println("\nSecurity Features:")
	fmt.Println("  ✓ Cryptographic signature prevents tampering")
	fmt.Println("  ✓ Timestamp prevents replay attacks")
	fmt.Println("  ✓ Nonce ensures request uniqueness")
	fmt.Println("  ✓ Query parameters included in signature")
}
