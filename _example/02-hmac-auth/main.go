package main

import (
	"bytes"
	"fmt"
	"log"
	"net/http"

	"github.com/appleboy/go-httpclient"
)

func main() {
	// Create auth config with HMAC mode
	auth := httpclient.NewAuthConfig(httpclient.AuthModeHMAC, "my-shared-secret")

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

	// Add HMAC authentication headers
	if err := auth.AddAuthHeaders(req, reqBody); err != nil {
		log.Fatalf("Failed to add auth headers: %v", err)
	}

	// Print request details for demonstration
	fmt.Println("Request Details:")
	fmt.Printf("  Method: %s\n", req.Method)
	fmt.Printf("  URL: %s\n", req.URL.String())
	fmt.Printf("  Body: %s\n", string(reqBody))
	fmt.Println("\nAuthentication Headers:")
	fmt.Printf("  X-Signature: %s\n", req.Header.Get("X-Signature"))
	fmt.Printf("  X-Timestamp: %s\n", req.Header.Get("X-Timestamp"))
	fmt.Printf("  X-Nonce: %s\n", req.Header.Get("X-Nonce"))

	// Send request (commented out to avoid actual HTTP call)
	// client := &http.Client{}
	// resp, err := client.Do(req)
	// if err != nil {
	// 	log.Fatalf("Request failed: %v", err)
	// }
	// defer resp.Body.Close()

	fmt.Println("\nHMAC authentication headers added successfully!")
	fmt.Println("\nSignature Calculation:")
	fmt.Println("  message = timestamp + method + path + query + body")
	fmt.Println("  signature = HMAC-SHA256(secret, message)")
	fmt.Println("\nSecurity Features:")
	fmt.Println("  ✓ Cryptographic signature prevents tampering")
	fmt.Println("  ✓ Timestamp prevents replay attacks")
	fmt.Println("  ✓ Nonce ensures request uniqueness")
	fmt.Println("  ✓ Query parameters included in signature")
}
