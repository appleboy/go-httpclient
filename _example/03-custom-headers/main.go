package main

import (
	"bytes"
	"fmt"
	"log"
	"net/http"

	"github.com/appleboy/go-httpclient"
)

func main() {
	fmt.Println("=== Example 1: Custom Simple Auth Header ===\n")
	simpleAuthExample()

	fmt.Println("\n\n=== Example 2: Custom HMAC Headers ===\n")
	hmacAuthExample()
}

func simpleAuthExample() {
	// Create auth config with custom header name
	auth := httpclient.NewAuthConfig(httpclient.AuthModeSimple, "my-api-key")
	auth.HeaderName = "Authorization" // Custom header name

	// Create request
	req, err := http.NewRequest(
		http.MethodGet,
		"https://api.example.com/data",
		nil,
	)
	if err != nil {
		log.Fatalf("Failed to create request: %v", err)
	}

	// Add authentication header
	if err := auth.AddAuthHeaders(req, nil); err != nil {
		log.Fatalf("Failed to add auth headers: %v", err)
	}

	// Print headers
	fmt.Println("Request Headers:")
	fmt.Printf("  Authorization: %s\n", req.Header.Get("Authorization"))
	fmt.Println("\nNote: Using 'Authorization' instead of default 'X-API-Secret'")
}

func hmacAuthExample() {
	// Create auth config with custom HMAC headers
	auth := httpclient.NewAuthConfig(httpclient.AuthModeHMAC, "shared-secret")
	auth.SignatureHeader = "X-Request-Signature"
	auth.TimestampHeader = "X-Request-Time"
	auth.NonceHeader = "X-Request-ID"

	// Create request
	reqBody := []byte(`{"data": "example"}`)
	req, err := http.NewRequest(
		http.MethodPost,
		"https://api.example.com/submit",
		bytes.NewBuffer(reqBody),
	)
	if err != nil {
		log.Fatalf("Failed to create request: %v", err)
	}

	// Add authentication headers
	if err := auth.AddAuthHeaders(req, reqBody); err != nil {
		log.Fatalf("Failed to add auth headers: %v", err)
	}

	// Print custom headers
	fmt.Println("Request Headers:")
	fmt.Printf("  X-Request-Signature: %s\n", req.Header.Get("X-Request-Signature"))
	fmt.Printf("  X-Request-Time: %s\n", req.Header.Get("X-Request-Time"))
	fmt.Printf("  X-Request-ID: %s\n", req.Header.Get("X-Request-ID"))

	fmt.Println("\nCustom Header Mappings:")
	fmt.Println("  Default           → Custom")
	fmt.Println("  X-Signature       → X-Request-Signature")
	fmt.Println("  X-Timestamp       → X-Request-Time")
	fmt.Println("  X-Nonce           → X-Request-ID")
}
