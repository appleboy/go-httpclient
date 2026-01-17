package main

import (
	"bytes"
	"fmt"
	"io"
	"log"
	"net/http"
	"time"

	"httpclient"
)

func main() {
	// Start HTTP server
	http.HandleFunc("/api/data", authMiddleware(dataHandler))

	fmt.Println("Server starting on http://localhost:8080")
	fmt.Println("Testing with sample requests...\n")

	// Wait a moment for server to start
	go func() {
		if err := http.ListenAndServe(":8080", nil); err != nil {
			log.Fatalf("Server failed: %v", err)
		}
	}()
	time.Sleep(100 * time.Millisecond)

	// Test 1: Valid HMAC request
	fmt.Println("=== Test 1: Valid HMAC Request ===")
	sendValidRequest()

	// Test 2: Invalid signature
	fmt.Println("\n=== Test 2: Invalid Signature ===")
	sendInvalidSignature()

	// Test 3: Expired timestamp
	fmt.Println("\n=== Test 3: Expired Timestamp ===")
	sendExpiredRequest()

	// Test 4: Missing headers
	fmt.Println("\n=== Test 4: Missing Headers ===")
	sendMissingHeaders()

	// Keep server running
	fmt.Println("\n\nServer is running. Press Ctrl+C to stop.")
	select {}
}

// authMiddleware verifies HMAC signature before passing to handler
func authMiddleware(next http.HandlerFunc) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		// Create auth config with same secret as client
		auth := httpclient.NewAuthConfig(httpclient.AuthModeHMAC, "shared-secret-key")

		// Verify HMAC signature (max age: 5 minutes)
		if err := auth.VerifyHMACSignature(r, 5*time.Minute); err != nil {
			http.Error(w, fmt.Sprintf("Authentication failed: %v", err), http.StatusUnauthorized)
			fmt.Printf("  ❌ Authentication failed: %v\n", err)
			return
		}

		fmt.Println("  ✅ Authentication successful")
		next(w, r)
	}
}

// dataHandler processes authenticated requests
func dataHandler(w http.ResponseWriter, r *http.Request) {
	// Read request body (already restored by VerifyHMACSignature)
	body, _ := io.ReadAll(r.Body)

	fmt.Printf("  📦 Received: %s\n", string(body))

	// Send response
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(http.StatusOK)
	fmt.Fprintf(w, `{"status": "success", "message": "Data received"}`)
}

// sendValidRequest sends a properly authenticated request
func sendValidRequest() {
	auth := httpclient.NewAuthConfig(httpclient.AuthModeHMAC, "shared-secret-key")

	reqBody := []byte(`{"action": "read", "resource": "data"}`)
	req, _ := http.NewRequest(
		http.MethodPost,
		"http://localhost:8080/api/data",
		bytes.NewBuffer(reqBody),
	)

	auth.AddAuthHeaders(req, reqBody)

	client := &http.Client{}
	resp, err := client.Do(req)
	if err != nil {
		fmt.Printf("  ❌ Request failed: %v\n", err)
		return
	}
	defer resp.Body.Close()

	body, _ := io.ReadAll(resp.Body)
	fmt.Printf("  📨 Response (%d): %s\n", resp.StatusCode, string(body))
}

// sendInvalidSignature sends request with wrong signature
func sendInvalidSignature() {
	reqBody := []byte(`{"action": "read"}`)
	req, _ := http.NewRequest(
		http.MethodPost,
		"http://localhost:8080/api/data",
		bytes.NewBuffer(reqBody),
	)

	// Add invalid headers
	req.Header.Set("X-Signature", "invalid-signature")
	req.Header.Set("X-Timestamp", fmt.Sprintf("%d", time.Now().Unix()))
	req.Header.Set("X-Nonce", "test-nonce")

	client := &http.Client{}
	resp, err := client.Do(req)
	if err != nil {
		fmt.Printf("  ❌ Request failed: %v\n", err)
		return
	}
	defer resp.Body.Close()

	body, _ := io.ReadAll(resp.Body)
	fmt.Printf("  📨 Response (%d): %s\n", resp.StatusCode, string(body))
}

// sendExpiredRequest sends request with old timestamp
func sendExpiredRequest() {
	reqBody := []byte(`{"action": "read"}`)
	req, _ := http.NewRequest(
		http.MethodPost,
		"http://localhost:8080/api/data",
		bytes.NewBuffer(reqBody),
	)

	// Set timestamp to 10 minutes ago (exceeds 5-minute limit)
	oldTimestamp := time.Now().Add(-10 * time.Minute).Unix()

	// Even with correct signature format, expired timestamp will be rejected
	req.Header.Set("X-Signature", "some-signature-value")
	req.Header.Set("X-Timestamp", fmt.Sprintf("%d", oldTimestamp))
	req.Header.Set("X-Nonce", "test-nonce")

	client := &http.Client{}
	resp, err := client.Do(req)
	if err != nil {
		fmt.Printf("  ❌ Request failed: %v\n", err)
		return
	}
	defer resp.Body.Close()

	body, _ := io.ReadAll(resp.Body)
	fmt.Printf("  📨 Response (%d): %s\n", resp.StatusCode, string(body))
}

// sendMissingHeaders sends request without authentication headers
func sendMissingHeaders() {
	reqBody := []byte(`{"action": "read"}`)
	req, _ := http.NewRequest(
		http.MethodPost,
		"http://localhost:8080/api/data",
		bytes.NewBuffer(reqBody),
	)

	client := &http.Client{}
	resp, err := client.Do(req)
	if err != nil {
		fmt.Printf("  ❌ Request failed: %v\n", err)
		return
	}
	defer resp.Body.Close()

	body, _ := io.ReadAll(resp.Body)
	fmt.Printf("  📨 Response (%d): %s\n", resp.StatusCode, string(body))
}
