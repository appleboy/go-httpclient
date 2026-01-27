package main

import (
	"bytes"
	"fmt"
	"log"
	"net/http"

	"github.com/appleboy/go-httpclient"
)

func main() {
	// Create HTTP client with simple authentication mode
	// Authentication headers are added automatically to all requests
	client, err := httpclient.NewAuthClient(httpclient.AuthModeSimple, "my-secret-api-key")
	if err != nil {
		log.Fatalf("Failed to create client: %v", err)
	}

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

	fmt.Println("Making request with automatic simple authentication...")
	fmt.Println("The X-API-Secret header will be added automatically by the client.")

	// Send request (commented out to avoid actual HTTP call)
	// The client automatically adds authentication headers before sending
	// resp, err := client.Do(req)
	// if err != nil {
	// 	log.Fatalf("Request failed: %v", err)
	// }
	// defer resp.Body.Close()
	//
	// body, _ := io.ReadAll(resp.Body)
	// fmt.Printf("\nResponse Status: %s\n", resp.Status)
	// fmt.Printf("Response Body: %s\n", string(body))

	fmt.Println("\nClient configured successfully!")
	fmt.Println(
		"All requests made with this client will automatically include the X-API-Secret header.",
	)

	// Silence "declared and not used" error for demonstration
	_ = client
	_ = req

	// Demonstrate that you can also use client.Get(), client.Post(), etc.
	fmt.Println("\nYou can also use convenience methods:")
	fmt.Println("  client.Get(url)")
	fmt.Println("  client.Post(url, contentType, body)")
	fmt.Println("  client.PostForm(url, data)")
}
