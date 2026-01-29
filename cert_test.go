package httpclient

import (
	"context"
	"crypto/rand"
	"crypto/rsa"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"io"
	"math/big"
	"net"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

// generateTestCertificate creates a self-signed certificate for testing
func generateTestCertificate() (certPEM, keyPEM []byte, err error) {
	// Generate private key
	privateKey, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		return nil, nil, err
	}

	// Create certificate template
	template := x509.Certificate{
		SerialNumber: big.NewInt(1),
		Subject: pkix.Name{
			Organization: []string{"Test Company"},
			CommonName:   "localhost",
		},
		NotBefore:             time.Now(),
		NotAfter:              time.Now().Add(365 * 24 * time.Hour),
		KeyUsage:              x509.KeyUsageKeyEncipherment | x509.KeyUsageDigitalSignature,
		ExtKeyUsage:           []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
		BasicConstraintsValid: true,
		DNSNames:              []string{"localhost"},
		IPAddresses:           []net.IP{net.ParseIP("127.0.0.1")},
	}

	// Create certificate
	certDER, err := x509.CreateCertificate(
		rand.Reader,
		&template,
		&template,
		&privateKey.PublicKey,
		privateKey,
	)
	if err != nil {
		return nil, nil, err
	}

	// Encode certificate to PEM
	certPEM = pem.EncodeToMemory(&pem.Block{
		Type:  "CERTIFICATE",
		Bytes: certDER,
	})

	// Encode private key to PEM
	keyPEM = pem.EncodeToMemory(&pem.Block{
		Type:  "RSA PRIVATE KEY",
		Bytes: x509.MarshalPKCS1PrivateKey(privateKey),
	})

	return certPEM, keyPEM, nil
}

// TestWithTLSCertFromBytes tests loading certificate from byte content
func TestWithTLSCertFromBytes(t *testing.T) {
	// Generate test certificate
	certPEM, keyPEM, err := generateTestCertificate()
	if err != nil {
		t.Fatalf("Failed to generate test certificate: %v", err)
	}

	// Create TLS certificate
	cert, err := tls.X509KeyPair(certPEM, keyPEM)
	if err != nil {
		t.Fatalf("Failed to create X509 key pair: %v", err)
	}

	// Create HTTPS test server
	server := httptest.NewUnstartedServer(
		http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			w.WriteHeader(http.StatusOK)
			_, _ = w.Write([]byte("Hello from HTTPS"))
		}),
	)
	server.TLS = &tls.Config{
		Certificates: []tls.Certificate{cert},
		MinVersion:   tls.VersionTLS12,
	}
	server.StartTLS()
	defer server.Close()

	// Create client with custom certificate
	client, err := NewAuthClient(
		AuthModeNone,
		"",
		WithTLSCertFromBytes(certPEM),
	)
	if err != nil {
		t.Fatalf("Failed to create client: %v", err)
	}

	// Make request
	req, err := http.NewRequestWithContext(context.Background(), http.MethodGet, server.URL, nil)
	if err != nil {
		t.Fatalf("Failed to create request: %v", err)
	}

	resp, err := client.Do(req)
	if err != nil {
		t.Fatalf("Request failed: %v", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		t.Errorf("Expected status 200, got %d", resp.StatusCode)
	}
}

// TestWithTLSCertFromFile tests loading certificate from file
func TestWithTLSCertFromFile(t *testing.T) {
	// Generate test certificate
	certPEM, keyPEM, err := generateTestCertificate()
	if err != nil {
		t.Fatalf("Failed to generate test certificate: %v", err)
	}

	// Create temporary directory for test files
	tempDir := t.TempDir()
	certFile := filepath.Join(tempDir, "test-ca.crt")
	keyFile := filepath.Join(tempDir, "test-key.pem")

	// Write certificate to file
	if err = os.WriteFile(certFile, certPEM, 0o600); err != nil {
		t.Fatalf("Failed to write certificate file: %v", err)
	}

	if err = os.WriteFile(keyFile, keyPEM, 0o600); err != nil {
		t.Fatalf("Failed to write key file: %v", err)
	}

	// Create TLS certificate
	cert, err := tls.X509KeyPair(certPEM, keyPEM)
	if err != nil {
		t.Fatalf("Failed to create X509 key pair: %v", err)
	}

	// Create HTTPS test server
	server := httptest.NewUnstartedServer(
		http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			w.WriteHeader(http.StatusOK)
			_, _ = w.Write([]byte("Hello from HTTPS"))
		}),
	)
	server.TLS = &tls.Config{
		Certificates: []tls.Certificate{cert},
		MinVersion:   tls.VersionTLS12,
	}
	server.StartTLS()
	defer server.Close()

	// Create client with certificate from file
	client, err := NewAuthClient(
		AuthModeNone,
		"",
		WithTLSCertFromFile(certFile),
	)
	if err != nil {
		t.Fatalf("Failed to create client: %v", err)
	}

	// Make request
	req, err := http.NewRequestWithContext(context.Background(), http.MethodGet, server.URL, nil)
	if err != nil {
		t.Fatalf("Failed to create request: %v", err)
	}

	resp, err := client.Do(req)
	if err != nil {
		t.Fatalf("Request failed: %v", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		t.Errorf("Expected status 200, got %d", resp.StatusCode)
	}
}

// TestWithTLSCertFromURL tests loading certificate from URL
func TestWithTLSCertFromURL(t *testing.T) {
	// Generate test certificate
	certPEM, keyPEM, err := generateTestCertificate()
	if err != nil {
		t.Fatalf("Failed to generate test certificate: %v", err)
	}

	// Create HTTP server to serve the certificate
	certServer := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/x-pem-file")
		_, _ = w.Write(certPEM)
	}))
	defer certServer.Close()

	// Create TLS certificate
	cert, err := tls.X509KeyPair(certPEM, keyPEM)
	if err != nil {
		t.Fatalf("Failed to create X509 key pair: %v", err)
	}

	// Create HTTPS test server
	server := httptest.NewUnstartedServer(
		http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			w.WriteHeader(http.StatusOK)
			_, _ = w.Write([]byte("Hello from HTTPS"))
		}),
	)
	server.TLS = &tls.Config{
		Certificates: []tls.Certificate{cert},
		MinVersion:   tls.VersionTLS12,
	}
	server.StartTLS()
	defer server.Close()

	// Create client with certificate from URL
	client, err := NewAuthClient(
		AuthModeNone,
		"",
		WithTLSCertFromURL(context.Background(), certServer.URL),
	)
	if err != nil {
		t.Fatalf("Failed to create client: %v", err)
	}

	// Make request
	req, err := http.NewRequestWithContext(context.Background(), http.MethodGet, server.URL, nil)
	if err != nil {
		t.Fatalf("Failed to create request: %v", err)
	}

	resp, err := client.Do(req)
	if err != nil {
		t.Fatalf("Request failed: %v", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		t.Errorf("Expected status 200, got %d", resp.StatusCode)
	}
}

// TestMultipleTLSCerts tests loading multiple certificates
func TestMultipleTLSCerts(t *testing.T) {
	// Generate two test certificates
	certPEM1, keyPEM1, err := generateTestCertificate()
	if err != nil {
		t.Fatalf("Failed to generate first test certificate: %v", err)
	}

	certPEM2, _, err := generateTestCertificate()
	if err != nil {
		t.Fatalf("Failed to generate second test certificate: %v", err)
	}

	// Create TLS certificate
	cert, err := tls.X509KeyPair(certPEM1, keyPEM1)
	if err != nil {
		t.Fatalf("Failed to create X509 key pair: %v", err)
	}

	// Create HTTPS test server
	server := httptest.NewUnstartedServer(
		http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			w.WriteHeader(http.StatusOK)
		}),
	)
	server.TLS = &tls.Config{
		Certificates: []tls.Certificate{cert},
		MinVersion:   tls.VersionTLS12,
	}
	server.StartTLS()
	defer server.Close()

	// Create temporary directory for test files
	tempDir := t.TempDir()
	certFile := filepath.Join(tempDir, "test-ca2.crt")
	if err := os.WriteFile(certFile, certPEM2, 0o600); err != nil {
		t.Fatalf("Failed to write certificate file: %v", err)
	}

	// Create client with multiple certificates
	client, err := NewAuthClient(
		AuthModeHMAC,
		"secret",
		WithTLSCertFromBytes(certPEM1),
		WithTLSCertFromFile(certFile),
	)
	if err != nil {
		t.Fatalf("Failed to create client: %v", err)
	}

	// Make request
	req, err := http.NewRequestWithContext(context.Background(), http.MethodGet, server.URL, nil)
	if err != nil {
		t.Fatalf("Failed to create request: %v", err)
	}

	resp, err := client.Do(req)
	if err != nil {
		t.Fatalf("Request failed: %v", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		t.Errorf("Expected status 200, got %d", resp.StatusCode)
	}
}

// TestTLSCertWithCustomTransport tests certificate loading with custom transport
func TestTLSCertWithCustomTransport(t *testing.T) {
	// Generate test certificate
	certPEM, keyPEM, err := generateTestCertificate()
	if err != nil {
		t.Fatalf("Failed to generate test certificate: %v", err)
	}

	// Create TLS certificate
	cert, err := tls.X509KeyPair(certPEM, keyPEM)
	if err != nil {
		t.Fatalf("Failed to create X509 key pair: %v", err)
	}

	// Create HTTPS test server
	server := httptest.NewUnstartedServer(
		http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			w.WriteHeader(http.StatusOK)
		}),
	)
	server.TLS = &tls.Config{
		Certificates: []tls.Certificate{cert},
		MinVersion:   tls.VersionTLS12,
	}
	server.StartTLS()
	defer server.Close()

	// Create custom transport
	customTransport := &http.Transport{
		MaxIdleConns: 10,
	}

	// Create client with custom transport and certificate
	client, err := NewAuthClient(
		AuthModeSimple,
		"secret",
		WithTransport(customTransport),
		WithTLSCertFromBytes(certPEM),
	)
	if err != nil {
		t.Fatalf("Failed to create client: %v", err)
	}

	// Make request
	req, err := http.NewRequestWithContext(context.Background(), http.MethodGet, server.URL, nil)
	if err != nil {
		t.Fatalf("Failed to create request: %v", err)
	}

	resp, err := client.Do(req)
	if err != nil {
		t.Fatalf("Request failed: %v", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		t.Errorf("Expected status 200, got %d", resp.StatusCode)
	}
}

// TestTLSCertWithNonTransportRoundTripper tests that TLS configuration works
// with custom RoundTrippers that are not *http.Transport, using the wrapper pattern.
func TestTLSCertWithNonTransportRoundTripper(t *testing.T) {
	// Generate test certificate
	certPEM, keyPEM, err := generateTestCertificate()
	if err != nil {
		t.Fatalf("Failed to generate test certificate: %v", err)
	}

	// Create TLS certificate
	cert, err := tls.X509KeyPair(certPEM, keyPEM)
	if err != nil {
		t.Fatalf("Failed to create X509 key pair: %v", err)
	}

	// Create HTTPS test server
	httpsServer := httptest.NewUnstartedServer(
		http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			w.WriteHeader(http.StatusOK)
			_, _ = w.Write([]byte("HTTPS"))
		}),
	)
	httpsServer.TLS = &tls.Config{
		Certificates: []tls.Certificate{cert},
		MinVersion:   tls.VersionTLS12,
	}
	httpsServer.StartTLS()
	defer httpsServer.Close()

	// Create HTTP test server for testing delegation
	httpServer := httptest.NewServer(
		http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			w.WriteHeader(http.StatusOK)
			_, _ = w.Write([]byte("HTTP"))
		}),
	)
	defer httpServer.Close()

	// Track if custom RoundTripper was used for HTTP requests
	httpRequestUsedCustom := false

	// Create custom non-*http.Transport RoundTripper
	customRoundTripper := &testNonTransportRoundTripper{
		base: http.DefaultTransport,
		onHTTPRequest: func(req *http.Request) {
			if req.URL.Scheme == "http" {
				httpRequestUsedCustom = true
			}
		},
	}

	// Create client with custom RoundTripper and TLS certificate
	client, err := NewAuthClient(
		AuthModeSimple,
		"secret",
		WithTransport(customRoundTripper),
		WithTLSCertFromBytes(certPEM),
	)
	if err != nil {
		t.Fatalf("Failed to create client: %v", err)
	}

	// Test 1: HTTPS request should work with TLS wrapper (using TLS transport)
	t.Run("HTTPS with TLS wrapper", func(t *testing.T) {
		req, err := http.NewRequestWithContext(
			context.Background(),
			http.MethodGet,
			httpsServer.URL,
			nil,
		)
		if err != nil {
			t.Fatalf("Failed to create request: %v", err)
		}

		resp, err := client.Do(req)
		if err != nil {
			t.Fatalf("HTTPS request failed: %v", err)
		}
		defer resp.Body.Close()

		if resp.StatusCode != http.StatusOK {
			t.Errorf("Expected status 200, got %d", resp.StatusCode)
		}

		body, _ := io.ReadAll(resp.Body)
		if string(body) != "HTTPS" {
			t.Errorf("Expected 'HTTPS', got %q", string(body))
		}
	})

	// Test 2: HTTP request should delegate to custom RoundTripper
	t.Run("HTTP delegates to custom RoundTripper", func(t *testing.T) {
		req, err := http.NewRequestWithContext(
			context.Background(),
			http.MethodGet,
			httpServer.URL,
			nil,
		)
		if err != nil {
			t.Fatalf("Failed to create request: %v", err)
		}

		resp, err := client.Do(req)
		if err != nil {
			t.Fatalf("HTTP request failed: %v", err)
		}
		defer resp.Body.Close()

		if resp.StatusCode != http.StatusOK {
			t.Errorf("Expected status 200, got %d", resp.StatusCode)
		}

		if !httpRequestUsedCustom {
			t.Error("HTTP request should have used custom RoundTripper")
		}
	})
}

// testNonTransportRoundTripper is a custom RoundTripper that is NOT *http.Transport.
// Used to test the tlsRoundTripperWrapper pattern.
type testNonTransportRoundTripper struct {
	base          http.RoundTripper
	onHTTPRequest func(*http.Request)
}

func (t *testNonTransportRoundTripper) RoundTrip(req *http.Request) (*http.Response, error) {
	if t.onHTTPRequest != nil {
		t.onHTTPRequest(req)
	}
	return t.base.RoundTrip(req)
}

// TestTLSCertFromFile_NonExistent tests error handling for non-existent file
func TestTLSCertFromFile_NonExistent(t *testing.T) {
	// Create client with non-existent certificate file
	client, err := NewAuthClient(
		AuthModeNone,
		"",
		WithTLSCertFromFile("/non/existent/path/cert.pem"),
	)

	// Should return error for non-existent file
	if err == nil {
		t.Fatal("Expected error for non-existent file")
	}
	if client != nil {
		t.Fatal("Expected nil client on error")
	}
}

// TestTLSCertFromURL_InvalidURL tests error handling for invalid URL
func TestTLSCertFromURL_InvalidURL(t *testing.T) {
	// Create client with invalid URL
	client, err := NewAuthClient(
		AuthModeNone,
		"",
		WithTLSCertFromURL(context.Background(), "http://invalid-url-that-does-not-exist.local"),
	)

	// Should return error for invalid URL
	if err == nil {
		t.Fatal("Expected error for invalid URL")
	}
	if client != nil {
		t.Fatal("Expected nil client on error")
	}
}

// TestTLSCertFromBytes_Invalid tests handling of invalid certificate data
func TestTLSCertFromBytes_Invalid(t *testing.T) {
	// Create client with invalid certificate data
	client, err := NewAuthClient(
		AuthModeNone,
		"",
		WithTLSCertFromBytes([]byte("not a valid certificate")),
	)
	if err != nil {
		t.Fatalf("Failed to create client: %v", err)
	}

	// The client should be created successfully (invalid certs are skipped)
	if client == nil {
		t.Fatal("Expected non-nil client")
	}
}

// TestTLSCertFromURL_OversizedCertificate tests protection against memory exhaustion
func TestTLSCertFromURL_OversizedCertificate(t *testing.T) {
	// Create a test server that returns a certificate exceeding 1MB
	oversizedData := make([]byte, 2*1024*1024) // 2MB
	for i := range oversizedData {
		oversizedData[i] = 'A'
	}

	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
		_, _ = w.Write(oversizedData)
	}))
	defer server.Close()

	// Creating client with oversized certificate should return error
	client, err := NewAuthClient(
		AuthModeNone,
		"",
		WithTLSCertFromURL(context.Background(), server.URL),
	)

	// Should return error for oversized certificate
	if err == nil {
		t.Fatal("Expected error when certificate exceeds maximum size")
	}
	if client != nil {
		t.Fatal("Expected nil client on error")
	}
	if !strings.Contains(err.Error(), "exceeds maximum size") {
		t.Errorf("Expected error message about size limit, got: %s", err.Error())
	}
}

// TestTLSCertFromFile_OversizedCertificate tests file size protection
func TestTLSCertFromFile_OversizedCertificate(t *testing.T) {
	// Create a temporary oversized certificate file
	tmpFile, err := os.CreateTemp("", "oversized-cert-*.pem")
	if err != nil {
		t.Fatalf("Failed to create temp file: %v", err)
	}
	defer os.Remove(tmpFile.Name())

	// Write 2MB of data
	oversizedData := make([]byte, 2*1024*1024)
	for i := range oversizedData {
		oversizedData[i] = 'A'
	}
	if _, err := tmpFile.Write(oversizedData); err != nil {
		t.Fatalf("Failed to write temp file: %v", err)
	}
	_ = tmpFile.Close()

	// Creating client with oversized certificate should return error
	client, err := NewAuthClient(
		AuthModeNone,
		"",
		WithTLSCertFromFile(tmpFile.Name()),
	)

	// Should return error for oversized certificate
	if err == nil {
		t.Fatal("Expected error when certificate file exceeds maximum size")
	}
	if client != nil {
		t.Fatal("Expected nil client on error")
	}
	if !strings.Contains(err.Error(), "exceeds maximum size") {
		t.Errorf("Expected error message about size limit, got: %s", err.Error())
	}
}

// TestTLSCertFromBytes_OversizedCertificate tests byte slice size validation
func TestTLSCertFromBytes_OversizedCertificate(t *testing.T) {
	// Create oversized certificate data (2MB)
	oversizedData := make([]byte, 2*1024*1024)
	for i := range oversizedData {
		oversizedData[i] = 'A'
	}

	// Creating client with oversized certificate should return error
	client, err := NewAuthClient(
		AuthModeNone,
		"",
		WithTLSCertFromBytes(oversizedData),
	)

	// Should return error for oversized certificate
	if err == nil {
		t.Fatal("Expected error when certificate bytes exceed maximum size")
	}
	if client != nil {
		t.Fatal("Expected nil client on error")
	}
	if !strings.Contains(err.Error(), "exceeds maximum size") {
		t.Errorf("Expected error message about size limit, got: %s", err.Error())
	}
}
