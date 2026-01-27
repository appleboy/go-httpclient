package httpclient

import (
	"context"
	"crypto/rand"
	"crypto/rsa"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
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

// generateClientCertificate creates a self-signed client certificate for mTLS testing
func generateClientCertificate() (certPEM, keyPEM []byte, err error) {
	// Generate private key
	privateKey, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		return nil, nil, err
	}

	// Create certificate template for client authentication
	template := x509.Certificate{
		SerialNumber: big.NewInt(2),
		Subject: pkix.Name{
			Organization: []string{"Test Client"},
			CommonName:   "test-client",
		},
		NotBefore:             time.Now(),
		NotAfter:              time.Now().Add(365 * 24 * time.Hour),
		KeyUsage:              x509.KeyUsageKeyEncipherment | x509.KeyUsageDigitalSignature,
		ExtKeyUsage:           []x509.ExtKeyUsage{x509.ExtKeyUsageClientAuth},
		BasicConstraintsValid: true,
	}

	// Create self-signed certificate
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

// generateCAAndClientCertificate creates a CA and a client certificate signed by that CA
// Returns: CA cert, CA key, client cert, client key, error
func generateCAAndClientCertificate() (caCertPEM, caKeyPEM, clientCertPEM, clientKeyPEM []byte, err error) {
	// Generate CA private key
	caPrivateKey, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		return nil, nil, nil, nil, err
	}

	// Create CA certificate template
	caTemplate := x509.Certificate{
		SerialNumber: big.NewInt(1),
		Subject: pkix.Name{
			Organization: []string{"Test CA"},
			CommonName:   "Test CA Root",
		},
		NotBefore: time.Now(),
		NotAfter:  time.Now().Add(10 * 365 * 24 * time.Hour),
		KeyUsage:  x509.KeyUsageKeyEncipherment | x509.KeyUsageDigitalSignature | x509.KeyUsageCertSign,
		ExtKeyUsage: []x509.ExtKeyUsage{
			x509.ExtKeyUsageServerAuth,
			x509.ExtKeyUsageClientAuth,
		},
		BasicConstraintsValid: true,
		IsCA:                  true,
		DNSNames:              []string{"localhost"},
		IPAddresses:           []net.IP{net.ParseIP("127.0.0.1")},
	}

	// Create self-signed CA certificate
	caCertDER, err := x509.CreateCertificate(
		rand.Reader,
		&caTemplate,
		&caTemplate,
		&caPrivateKey.PublicKey,
		caPrivateKey,
	)
	if err != nil {
		return nil, nil, nil, nil, err
	}

	// Encode CA certificate to PEM
	caCertPEM = pem.EncodeToMemory(&pem.Block{
		Type:  "CERTIFICATE",
		Bytes: caCertDER,
	})

	// Encode CA private key to PEM
	caKeyPEM = pem.EncodeToMemory(&pem.Block{
		Type:  "RSA PRIVATE KEY",
		Bytes: x509.MarshalPKCS1PrivateKey(caPrivateKey),
	})

	// Generate client private key
	clientPrivateKey, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		return nil, nil, nil, nil, err
	}

	// Create client certificate template
	clientTemplate := x509.Certificate{
		SerialNumber: big.NewInt(2),
		Subject: pkix.Name{
			Organization: []string{"Test Client"},
			CommonName:   "test-client",
		},
		NotBefore:             time.Now(),
		NotAfter:              time.Now().Add(365 * 24 * time.Hour),
		KeyUsage:              x509.KeyUsageKeyEncipherment | x509.KeyUsageDigitalSignature,
		ExtKeyUsage:           []x509.ExtKeyUsage{x509.ExtKeyUsageClientAuth},
		BasicConstraintsValid: true,
	}

	// Create client certificate signed by CA
	clientCertDER, err := x509.CreateCertificate(
		rand.Reader,
		&clientTemplate,
		&caTemplate, // Signed by CA
		&clientPrivateKey.PublicKey,
		caPrivateKey, // Signed by CA's private key
	)
	if err != nil {
		return nil, nil, nil, nil, err
	}

	// Encode client certificate to PEM
	clientCertPEM = pem.EncodeToMemory(&pem.Block{
		Type:  "CERTIFICATE",
		Bytes: clientCertDER,
	})

	// Encode client private key to PEM
	clientKeyPEM = pem.EncodeToMemory(&pem.Block{
		Type:  "RSA PRIVATE KEY",
		Bytes: x509.MarshalPKCS1PrivateKey(clientPrivateKey),
	})

	return caCertPEM, caKeyPEM, clientCertPEM, clientKeyPEM, nil
}

// TestWithMTLSFromBytes_Valid tests loading valid mTLS certificate from bytes
func TestWithMTLSFromBytes_Valid(t *testing.T) {
	// Generate CA and client certificates
	caCertPEM, caKeyPEM, clientCertPEM, clientKeyPEM, err := generateCAAndClientCertificate()
	if err != nil {
		t.Fatalf("Failed to generate certificates: %v", err)
	}

	// Parse CA certificate pool for client certificate verification
	caCertPool := x509.NewCertPool()
	if !caCertPool.AppendCertsFromPEM(caCertPEM) {
		t.Fatal("Failed to add CA certificate to pool")
	}

	// Use CA certificate as server certificate for simplicity
	serverCert, err := tls.X509KeyPair(caCertPEM, caKeyPEM)
	if err != nil {
		t.Fatalf("Failed to create server key pair: %v", err)
	}

	// Create mTLS-enabled test server
	server := httptest.NewUnstartedServer(
		http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			// Verify client certificate was provided
			if r.TLS == nil || len(r.TLS.PeerCertificates) == 0 {
				t.Error("Expected client certificate")
			}
			w.WriteHeader(http.StatusOK)
			_, _ = w.Write([]byte("mTLS success"))
		}),
	)
	server.TLS = &tls.Config{
		ClientAuth:   tls.RequireAndVerifyClientCert,
		ClientCAs:    caCertPool,
		Certificates: []tls.Certificate{serverCert},
		MinVersion:   tls.VersionTLS12,
	}
	server.StartTLS()
	defer server.Close()

	// Create client with mTLS certificate from bytes
	client, err := NewAuthClient(
		AuthModeNone,
		"",
		WithTLSCertFromBytes(caCertPEM), // Trust server's CA
		WithMTLSFromBytes(clientCertPEM, clientKeyPEM), // Client certificate
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

// TestWithMTLSFromFile_Valid tests loading mTLS certificate from files
func TestWithMTLSFromFile_Valid(t *testing.T) {
	// Generate client certificate
	certPEM, keyPEM, err := generateClientCertificate()
	if err != nil {
		t.Fatalf("Failed to generate certificate: %v", err)
	}

	// Create temporary directory for test files
	tempDir := t.TempDir()
	certFile := filepath.Join(tempDir, "client.crt")
	keyFile := filepath.Join(tempDir, "client.key")

	// Write certificate and key to files
	if err = os.WriteFile(certFile, certPEM, 0o600); err != nil {
		t.Fatalf("Failed to write certificate file: %v", err)
	}

	if err = os.WriteFile(keyFile, keyPEM, 0o600); err != nil {
		t.Fatalf("Failed to write key file: %v", err)
	}

	// Create client with mTLS certificate from files
	client, err := NewAuthClient(
		AuthModeNone,
		"",
		WithMTLSFromFile(certFile, keyFile),
	)
	if err != nil {
		t.Fatalf("Failed to create client: %v", err)
	}

	if client == nil {
		t.Fatal("Expected non-nil client")
	}

	// Verify the client has TLS config with client certificate
	transport, ok := client.Transport.(*authRoundTripper)
	if !ok {
		t.Fatal("Expected authRoundTripper")
	}

	httpTransport, ok := transport.transport.(*http.Transport)
	if !ok {
		t.Fatal("Expected http.Transport")
	}

	if httpTransport.TLSClientConfig == nil {
		t.Fatal("Expected TLS client config")
	}

	if len(httpTransport.TLSClientConfig.Certificates) == 0 {
		t.Error("Expected client certificates to be configured")
	}
}

// TestWithMTLSFromBytes_Invalid tests error handling for invalid certificate pair
func TestWithMTLSFromBytes_Invalid(t *testing.T) {
	invalidCert := []byte("not a valid certificate")
	invalidKey := []byte("not a valid key")

	// Attempt to create client with invalid certificate pair
	_, err := NewAuthClient(
		AuthModeNone,
		"",
		WithMTLSFromBytes(invalidCert, invalidKey),
	)

	if err == nil {
		t.Fatal("Expected error for invalid certificate pair, got nil")
	}

	if !strings.Contains(err.Error(), "invalid mTLS cert/key pair") {
		t.Errorf("Expected error message about invalid cert/key pair, got: %v", err)
	}
}

// TestWithMTLSFromFile_NonExistent tests error handling for non-existent files
func TestWithMTLSFromFile_NonExistent(t *testing.T) {
	nonExistentCert := "/nonexistent/path/cert.pem"
	nonExistentKey := "/nonexistent/path/key.pem"

	// Attempt to create client with non-existent files
	_, err := NewAuthClient(
		AuthModeNone,
		"",
		WithMTLSFromFile(nonExistentCert, nonExistentKey),
	)

	if err == nil {
		t.Fatal("Expected error for non-existent file, got nil")
	}

	if !strings.Contains(err.Error(), "failed to read mTLS cert") {
		t.Errorf("Expected error message about reading mTLS cert, got: %v", err)
	}
}

// TestWithMTLSFromFile_MismatchedPair tests error handling for mismatched cert/key pair
func TestWithMTLSFromFile_MismatchedPair(t *testing.T) {
	// Generate two different certificate pairs
	cert1PEM, _, err := generateClientCertificate()
	if err != nil {
		t.Fatalf("Failed to generate first certificate: %v", err)
	}

	_, key2PEM, err := generateClientCertificate()
	if err != nil {
		t.Fatalf("Failed to generate second certificate: %v", err)
	}

	// Create temporary directory for test files
	tempDir := t.TempDir()
	certFile := filepath.Join(tempDir, "cert.pem")
	keyFile := filepath.Join(tempDir, "key.pem")

	// Write mismatched certificate and key to files
	if err = os.WriteFile(certFile, cert1PEM, 0o600); err != nil {
		t.Fatalf("Failed to write certificate file: %v", err)
	}

	if err = os.WriteFile(keyFile, key2PEM, 0o600); err != nil {
		t.Fatalf("Failed to write key file: %v", err)
	}

	// Attempt to create client with mismatched cert/key pair
	_, err = NewAuthClient(
		AuthModeNone,
		"",
		WithMTLSFromFile(certFile, keyFile),
	)

	if err == nil {
		t.Fatal("Expected error for mismatched cert/key pair, got nil")
	}

	if !strings.Contains(err.Error(), "invalid mTLS cert/key pair") {
		t.Errorf("Expected error message about invalid cert/key pair, got: %v", err)
	}
}

// TestMTLS_Integration tests complete client-server mTLS handshake
func TestMTLS_Integration(t *testing.T) {
	// Generate CA and client certificates
	caCertPEM, caKeyPEM, clientCertPEM, clientKeyPEM, err := generateCAAndClientCertificate()
	if err != nil {
		t.Fatalf("Failed to generate certificates: %v", err)
	}

	// Parse CA certificate for both server and client
	caCertPool := x509.NewCertPool()
	if !caCertPool.AppendCertsFromPEM(caCertPEM) {
		t.Fatal("Failed to add CA certificate to pool")
	}

	// Use CA certificate as server certificate for simplicity
	serverCert, err := tls.X509KeyPair(caCertPEM, caKeyPEM)
	if err != nil {
		t.Fatalf("Failed to create server key pair: %v", err)
	}

	// Track if client certificate was verified
	clientCertVerified := false

	// Create mTLS-enabled test server
	server := httptest.NewUnstartedServer(
		http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			// Verify client certificate was provided and verified
			if r.TLS == nil || len(r.TLS.PeerCertificates) == 0 {
				t.Error("Expected client certificate in request")
				w.WriteHeader(http.StatusUnauthorized)
				return
			}

			clientCertVerified = true
			w.WriteHeader(http.StatusOK)
			_, _ = w.Write([]byte("mTLS authentication successful"))
		}),
	)
	server.TLS = &tls.Config{
		ClientAuth:   tls.RequireAndVerifyClientCert,
		ClientCAs:    caCertPool,
		Certificates: []tls.Certificate{serverCert},
		MinVersion:   tls.VersionTLS12,
	}
	server.StartTLS()
	defer server.Close()

	// Create client with mTLS certificate
	client, err := NewAuthClient(
		AuthModeHMAC,
		"test-secret",
		WithTLSCertFromBytes(caCertPEM), // Trust server's CA
		WithMTLSFromBytes(clientCertPEM, clientKeyPEM), // Client certificate
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

	if !clientCertVerified {
		t.Error("Client certificate was not verified by server")
	}
}

// TestMTLS_WithTLSCertCombined tests using both CA certificate and mTLS together
func TestMTLS_WithTLSCertCombined(t *testing.T) {
	// Generate server CA and certificates
	serverCACertPEM, serverCAKeyPEM, _, _, err := generateCAAndClientCertificate()
	if err != nil {
		t.Fatalf("Failed to generate server CA: %v", err)
	}

	// Generate client CA and certificates
	clientCACertPEM, _, clientCertPEM, clientKeyPEM, err := generateCAAndClientCertificate()
	if err != nil {
		t.Fatalf("Failed to generate client certificates: %v", err)
	}

	// Parse client certificate pool for server (to verify client certs)
	clientCertPool := x509.NewCertPool()
	if !clientCertPool.AppendCertsFromPEM(clientCACertPEM) {
		t.Fatal("Failed to add client CA certificate to pool")
	}

	// Create server certificate using server CA
	serverCert, err := tls.X509KeyPair(serverCACertPEM, serverCAKeyPEM)
	if err != nil {
		t.Fatalf("Failed to create server key pair: %v", err)
	}

	// Create test server with mTLS
	server := httptest.NewUnstartedServer(
		http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			// Verify client certificate was provided
			if r.TLS == nil || len(r.TLS.PeerCertificates) == 0 {
				t.Error("Expected client certificate")
				w.WriteHeader(http.StatusUnauthorized)
				return
			}
			w.WriteHeader(http.StatusOK)
			_, _ = w.Write([]byte("success"))
		}),
	)
	server.TLS = &tls.Config{
		ClientAuth:   tls.RequireAndVerifyClientCert,
		ClientCAs:    clientCertPool,
		Certificates: []tls.Certificate{serverCert},
		MinVersion:   tls.VersionTLS12,
	}
	server.StartTLS()
	defer server.Close()

	// Create client with both TLS CA cert and mTLS client cert
	client, err := NewAuthClient(
		AuthModeNone,
		"",
		WithTLSCertFromBytes(serverCACertPEM), // Trust server's CA
		WithMTLSFromBytes(clientCertPEM, clientKeyPEM), // Client certificate for mTLS
	)
	if err != nil {
		t.Fatalf("Failed to create client: %v", err)
	}

	// Verify both TLS CA and mTLS certificates are configured
	transport, ok := client.Transport.(*authRoundTripper)
	if !ok {
		t.Fatal("Expected authRoundTripper")
	}

	httpTransport, ok := transport.transport.(*http.Transport)
	if !ok {
		t.Fatal("Expected http.Transport")
	}

	if httpTransport.TLSClientConfig == nil {
		t.Fatal("Expected TLS client config")
	}

	if httpTransport.TLSClientConfig.RootCAs == nil {
		t.Error("Expected RootCAs to be configured")
	}

	if len(httpTransport.TLSClientConfig.Certificates) == 0 {
		t.Error("Expected client certificates to be configured")
	}

	// Make request to verify everything works together
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
