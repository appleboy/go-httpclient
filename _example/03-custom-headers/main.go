package main

import (
	"bytes"
	"fmt"
	"log"
	"net/http"

	"github.com/appleboy/go-httpclient"
)

func main() {
	fmt.Println("=== Example 1: Custom Simple Auth Header ===")
	simpleAuthExample()

	fmt.Println("\n\n=== Example 2: Custom HMAC Headers ===")
	hmacAuthExample()
}

func simpleAuthExample() {
	// Create HTTP client with custom header name for simple authentication
	client := httpclient.NewAuthClient(
		httpclient.AuthModeSimple,
		"my-api-key",
		httpclient.WithHeaderName("Authorization"), // Custom header name
	)

	// Create request
	req, err := http.NewRequest(
		http.MethodGet,
		"https://api.example.com/data",
		nil,
	)
	if err != nil {
		log.Fatalf("Failed to create request: %v", err)
	}

	fmt.Println("Client configured with custom header name")
	fmt.Println("The 'Authorization' header will be used instead of 'X-API-Secret'")

	// Send request (commented out to avoid actual HTTP call)
	// resp, err := client.Do(req)
	// if err != nil {
	// 	log.Fatalf("Request failed: %v", err)
	// }
	// defer resp.Body.Close()

	fmt.Println("\nNote: All requests made with this client will use the custom header name.")

	// Silence "declared and not used" error for demonstration
	_ = client
	_ = req
}

func hmacAuthExample() {
	// Create HTTP client with custom HMAC header names
	client := httpclient.NewAuthClient(
		httpclient.AuthModeHMAC,
		"shared-secret",
		httpclient.WithHMACHeaders(
			"X-Request-Signature", // Custom signature header
			"X-Request-Time",      // Custom timestamp header
			"X-Request-ID",        // Custom nonce header
		),
	)

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

	fmt.Println("Client configured with custom HMAC headers")
	fmt.Println("\nCustom Header Mappings:")
	fmt.Println("  Default           → Custom")
	fmt.Println("  X-Signature       → X-Request-Signature")
	fmt.Println("  X-Timestamp       → X-Request-Time")
	fmt.Println("  X-Nonce           → X-Request-ID")

	// Send request (commented out to avoid actual HTTP call)
	// resp, err := client.Do(req)
	// if err != nil {
	// 	log.Fatalf("Request failed: %v", err)
	// }
	// defer resp.Body.Close()

	fmt.Println("\nNote: All requests made with this client will use the custom header names.")

	// Silence "declared and not used" error for demonstration
	_ = client
	_ = req
}
