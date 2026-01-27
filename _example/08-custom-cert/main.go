package main

import (
	"context"
	"fmt"
	"log"
	"net/http"
	"time"

	"github.com/appleboy/go-httpclient"
)

func main() {
	// Example 1: Load certificate from file path
	client1, err := httpclient.NewAuthClient(
		httpclient.AuthModeHMAC,
		"your-secret-key",
		httpclient.WithTLSCertFromFile("/etc/ssl/certs/company-ca.crt"),
	)
	if err != nil {
		log.Fatalf("Failed to create client: %v", err)
	}

	// Example 2: Load certificate from URL (with context for timeout control)
	certCtx, certCancel := context.WithTimeout(context.Background(), 10*time.Second)
	client2, err := httpclient.NewAuthClient(
		httpclient.AuthModeHMAC,
		"your-secret-key",
		httpclient.WithTLSCertFromURL(certCtx, "https://internal-ca.company.com/ca.crt"),
	)
	certCancel() // Cancel context after client is created
	if err != nil {
		log.Fatalf("Failed to create client: %v", err)
	}

	// Example 3: Load certificate from byte content (embedded certificate)
	certPEM := []byte(`-----BEGIN CERTIFICATE-----
MIIDXTCCAkWgAwIBAgIJAKL0UG+mRKmdMA0GCSqGSIb3DQEBCwUAMEUxCzAJBgNV
BAYTAkFVMRMwEQYDVQQIDApTb21lLVN0YXRlMSEwHwYDVQQKDBhJbnRlcm5ldCBX
aWRnaXRzIFB0eSBMdGQwHhcNMjQwMTAxMDAwMDAwWhcNMzQwMTAxMDAwMDAwWjBF
... (your certificate content) ...
-----END CERTIFICATE-----`)

	client3, err := httpclient.NewAuthClient(
		httpclient.AuthModeHMAC,
		"your-secret-key",
		httpclient.WithTLSCertFromBytes(certPEM),
	)
	if err != nil {
		log.Fatalf("Failed to create client: %v", err)
	}

	// Example 4: Load multiple certificates from different sources
	client4, err := httpclient.NewAuthClient(
		httpclient.AuthModeHMAC,
		"your-secret-key",
		httpclient.WithTLSCertFromFile("/etc/ssl/certs/root-ca.crt"),
		httpclient.WithTLSCertFromFile("/etc/ssl/certs/intermediate-ca.crt"),
		httpclient.WithTLSCertFromBytes(certPEM),
	)
	if err != nil {
		log.Fatalf("Failed to create client: %v", err)
	}

	// Example 5: Combine with other options
	client5, err := httpclient.NewAuthClient(
		httpclient.AuthModeHMAC,
		"your-secret-key",
		httpclient.WithTLSCertFromFile("/etc/ssl/certs/company-ca.crt"),
		httpclient.WithTimeout(30*time.Second),
		httpclient.WithMaxBodySize(5*1024*1024), // 5MB
	)
	if err != nil {
		log.Fatalf("Failed to create client: %v", err)
	}

	// Example 6: Use with custom transport
	customTransport := &http.Transport{
		MaxIdleConns:        100,
		MaxIdleConnsPerHost: 10,
	}

	client6, err := httpclient.NewAuthClient(
		httpclient.AuthModeHMAC,
		"your-secret-key",
		httpclient.WithTransport(customTransport),
		httpclient.WithTLSCertFromFile("/etc/ssl/certs/company-ca.crt"),
	)
	if err != nil {
		log.Fatalf("Failed to create client: %v", err)
	}

	// Make a request using any of the clients
	req, err := http.NewRequestWithContext(
		context.Background(),
		http.MethodGet,
		"https://api.internal.company.com/data",
		nil,
	)
	if err != nil {
		log.Fatalf("Failed to create request: %v", err)
	}

	resp, err := client1.Do(req)
	if err != nil {
		log.Fatalf("Request failed: %v", err)
	}
	defer resp.Body.Close()

	fmt.Printf("Response status: %d\n", resp.StatusCode)

	// Use other clients as needed
	_ = client2
	_ = client3
	_ = client4
	_ = client5
	_ = client6
}
