package main

import (
	"context"
	"fmt"
	"log"
	"net/http"
	"net/http/httptest"
	"time"

	"github.com/appleboy/go-httpclient"
	"github.com/google/uuid"
)

func main() {
	// Example 1: Basic request ID with UUID
	fmt.Println("Example 1: Basic Request ID Tracking with UUID")
	fmt.Println("================================================")
	basicExample()

	fmt.Println("\nExample 2: Custom Request ID Format")
	fmt.Println("====================================")
	customFormatExample()

	fmt.Println("\nExample 3: Request ID with Custom Header Name")
	fmt.Println("=============================================")
	customHeaderExample()

	fmt.Println("\nExample 4: Request ID with Authentication")
	fmt.Println("==========================================")
	withAuthenticationExample()

	fmt.Println("\nExample 5: Preserving User-Provided Request IDs")
	fmt.Println("================================================")
	preserveUserIDExample()
}

// basicExample demonstrates basic request ID tracking using UUID
func basicExample() {
	// Create a test server that logs the request ID
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		requestID := r.Header.Get(httpclient.DefaultRequestIDHeader)
		fmt.Printf("  Server received request ID: %s\n", requestID)
		fmt.Fprintf(w, "Request ID: %s", requestID)
	}))
	defer server.Close()

	// Create client with UUID-based request ID generator
	client, err := httpclient.NewAuthClient(
		httpclient.AuthModeNone,
		"",
		httpclient.WithRequestID(func() string {
			return uuid.New().String()
		}),
	)
	if err != nil {
		log.Fatalf("Failed to create client: %v", err)
	}

	// Make a request
	req, _ := http.NewRequestWithContext(context.Background(), http.MethodGet, server.URL, nil)
	resp, err := client.Do(req)
	if err != nil {
		log.Fatalf("Request failed: %v", err)
	}
	defer resp.Body.Close()

	fmt.Printf("  Response status: %s\n", resp.Status)
}

// customFormatExample demonstrates custom request ID format
func customFormatExample() {
	var requestCounter int

	// Create a test server
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		requestID := r.Header.Get(httpclient.DefaultRequestIDHeader)
		fmt.Printf("  Server received request ID: %s\n", requestID)
		w.WriteHeader(http.StatusOK)
	}))
	defer server.Close()

	// Create client with custom request ID format
	client, err := httpclient.NewAuthClient(
		httpclient.AuthModeNone,
		"",
		httpclient.WithRequestID(func() string {
			requestCounter++
			return fmt.Sprintf("req-%d-%d", time.Now().Unix(), requestCounter)
		}),
	)
	if err != nil {
		log.Fatalf("Failed to create client: %v", err)
	}

	// Make multiple requests to show different IDs
	for i := 0; i < 3; i++ {
		req, _ := http.NewRequestWithContext(context.Background(), http.MethodGet, server.URL, nil)
		resp, err := client.Do(req)
		if err != nil {
			log.Fatalf("Request failed: %v", err)
		}
		_ = resp.Body.Close()
	}
}

// customHeaderExample demonstrates using a custom header name for request ID
func customHeaderExample() {
	customHeader := "X-Correlation-ID"

	// Create a test server
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		requestID := r.Header.Get(customHeader)
		fmt.Printf("  Server received correlation ID: %s\n", requestID)

		// Verify default header is not present
		if r.Header.Get(httpclient.DefaultRequestIDHeader) != "" {
			fmt.Println("  WARNING: Default header should not be present!")
		}

		w.WriteHeader(http.StatusOK)
	}))
	defer server.Close()

	// Create client with custom request ID header
	client, err := httpclient.NewAuthClient(
		httpclient.AuthModeNone,
		"",
		httpclient.WithRequestID(func() string {
			return uuid.New().String()
		}),
		httpclient.WithRequestIDHeader(customHeader),
	)
	if err != nil {
		log.Fatalf("Failed to create client: %v", err)
	}

	// Make a request
	req, _ := http.NewRequestWithContext(context.Background(), http.MethodGet, server.URL, nil)
	resp, err := client.Do(req)
	if err != nil {
		log.Fatalf("Request failed: %v", err)
	}
	defer resp.Body.Close()

	fmt.Printf("  Response status: %s\n", resp.Status)
}

// withAuthenticationExample demonstrates request ID tracking with HMAC authentication
func withAuthenticationExample() {
	secret := "shared-secret"

	// Create a test server that shows request ID and auth headers
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		requestID := r.Header.Get(httpclient.DefaultRequestIDHeader)
		signature := r.Header.Get(httpclient.DefaultSignatureHeader)
		timestamp := r.Header.Get(httpclient.DefaultTimestampHeader)
		nonce := r.Header.Get(httpclient.DefaultNonceHeader)

		fmt.Printf("  Request ID: %s\n", requestID[:8]+"...") // Show first 8 chars
		fmt.Printf("  Has HMAC signature: %v\n", signature != "")
		fmt.Printf("  Has timestamp: %v\n", timestamp != "")
		fmt.Printf("  Has nonce: %v\n", nonce != "")

		// In a real server, you would verify the signature here using:
		// auth := httpclient.NewAuthConfig(httpclient.AuthModeHMAC, secret)
		// if err := auth.Verify(r); err != nil { ... }

		fmt.Println("  ✓ All headers present")
		w.WriteHeader(http.StatusOK)
	}))
	defer server.Close()

	// Create client with both request ID and HMAC authentication
	client, err := httpclient.NewAuthClient(
		httpclient.AuthModeHMAC,
		secret,
		httpclient.WithRequestID(func() string {
			return uuid.New().String()
		}),
	)
	if err != nil {
		log.Fatalf("Failed to create client: %v", err)
	}

	// Make a request
	req, _ := http.NewRequestWithContext(context.Background(), http.MethodGet, server.URL, nil)
	resp, err := client.Do(req)
	if err != nil {
		log.Fatalf("Request failed: %v", err)
	}
	defer resp.Body.Close()

	fmt.Printf("  Response status: %s\n", resp.Status)
}

// preserveUserIDExample demonstrates that user-provided request IDs are preserved
func preserveUserIDExample() {
	userProvidedID := "user-custom-request-id-12345"

	// Create a test server
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		requestID := r.Header.Get(httpclient.DefaultRequestIDHeader)
		fmt.Printf("  Server received request ID: %s\n", requestID)

		if requestID == userProvidedID {
			fmt.Println("  ✓ User-provided request ID was preserved!")
		} else {
			fmt.Println("  ✗ User-provided request ID was NOT preserved!")
		}

		w.WriteHeader(http.StatusOK)
	}))
	defer server.Close()

	// Create client with request ID function
	client, err := httpclient.NewAuthClient(
		httpclient.AuthModeNone,
		"",
		httpclient.WithRequestID(func() string {
			return "auto-generated-id"
		}),
	)
	if err != nil {
		log.Fatalf("Failed to create client: %v", err)
	}

	// Make a request with user-provided request ID
	req, _ := http.NewRequestWithContext(context.Background(), http.MethodGet, server.URL, nil)
	req.Header.Set(httpclient.DefaultRequestIDHeader, userProvidedID)
	resp, err := client.Do(req)
	if err != nil {
		log.Fatalf("Request failed: %v", err)
	}
	defer resp.Body.Close()

	fmt.Printf("  Response status: %s\n", resp.Status)
}
