package main

import (
	"bytes"
	"fmt"
	"httpclient"
	"log"
	"net/http"
)

func main() {
	// Create auth config with simple mode
	auth := httpclient.NewAuthConfig(httpclient.AuthModeSimple, "my-secret-api-key")

	// Create HTTP request
	reqBody := []byte(`{"name": "John Doe", "email": "john@example.com"}`)
	req, err := http.NewRequest(
		http.MethodPost,
		"https://api.example.com/users",
		bytes.NewBuffer(reqBody),
	)
	if err != nil {
		log.Fatalf("Failed to create request: %v", err)
	}

	// Set content type
	req.Header.Set("Content-Type", "application/json")

	// Add authentication headers
	if err := auth.AddAuthHeaders(req, reqBody); err != nil {
		log.Fatalf("Failed to add auth headers: %v", err)
	}

	// Print request headers for demonstration
	fmt.Println("Request Headers:")
	for name, values := range req.Header {
		for _, value := range values {
			fmt.Printf("  %s: %s\n", name, value)
		}
	}

	// Send request (commented out to avoid actual HTTP call)
	// client := &http.Client{}
	// resp, err := client.Do(req)
	// if err != nil {
	// 	log.Fatalf("Request failed: %v", err)
	// }
	// defer resp.Body.Close()
	//
	// body, _ := io.ReadAll(resp.Body)
	// fmt.Printf("\nResponse Status: %s\n", resp.Status)
	// fmt.Printf("Response Body: %s\n", string(body))

	fmt.Println("\nSimple authentication header added successfully!")
	fmt.Println("The X-API-Secret header contains the API key for authentication.")
}
