package main

import (
	"fmt"
	"net/http"
	"time"

	"github.com/appleboy/go-httpclient"
)

// loggingTransport is a custom transport that logs requests
type loggingTransport struct {
	base http.RoundTripper
}

func (t *loggingTransport) RoundTrip(req *http.Request) (*http.Response, error) {
	fmt.Printf("[LOG] %s %s %s\n", time.Now().Format("15:04:05"), req.Method, req.URL)
	return t.base.RoundTrip(req)
}

// metricsTransport is a custom transport that collects metrics
type metricsTransport struct {
	base         http.RoundTripper
	requestCount int
}

func (t *metricsTransport) RoundTrip(req *http.Request) (*http.Response, error) {
	t.requestCount++
	fmt.Printf("[METRICS] Total requests: %d\n", t.requestCount)
	return t.base.RoundTrip(req)
}

func main() {
	fmt.Println("=== Transport Chaining Example ===\n")

	// Example 1: Simple transport chaining with WithTransport option
	fmt.Println("Example 1: Chaining authentication with logging")
	fmt.Println("  Request flow: Client → Auth → Logging → Base Transport\n")

	// Create base transport with custom settings
	baseTransport := &http.Transport{
		MaxIdleConns:       10,
		IdleConnTimeout:    30 * time.Second,
		DisableCompression: false,
	}

	// Wrap base transport with logging
	loggingT := &loggingTransport{
		base: baseTransport,
	}

	// Create authenticated client with logging transport
	client1 := httpclient.NewAuthClient(
		httpclient.AuthModeHMAC,
		"secret",
		httpclient.WithTransport(loggingT),
	)

	fmt.Println("  ✓ Client created with auth + logging")
	fmt.Println("    (requests will be logged before being sent)")
	_ = client1

	// Example 2: More complex chaining with metrics
	fmt.Println("\nExample 2: Chaining auth + metrics + logging")
	fmt.Println("  Request flow: Client → Auth → Metrics → Logging → Base Transport\n")

	// Create metrics transport
	metricsT := &metricsTransport{
		base: baseTransport,
	}

	// Wrap with logging
	loggingT2 := &loggingTransport{
		base: metricsT,
	}

	// Create authenticated client
	client2 := httpclient.NewAuthClient(
		httpclient.AuthModeHMAC,
		"secret",
		httpclient.WithTransport(loggingT2),
	)

	fmt.Println("  ✓ Client created with full chain")
	fmt.Println("    1. Authentication headers added")
	fmt.Println("    2. Request logged")
	fmt.Println("    3. Metrics collected")
	fmt.Println("    4. Request sent via base transport")
	_ = client2

	// Example 3: Real-world scenario
	fmt.Println("\nExample 3: Real-world scenario")
	fmt.Println("  Production setup with:")
	fmt.Println("  - Custom connection pool settings")
	fmt.Println("  - Request logging")
	fmt.Println("  - Automatic authentication")
	fmt.Println("  - Reasonable timeouts\n")

	prodTransport := &http.Transport{
		MaxIdleConns:          100,
		MaxIdleConnsPerHost:   10,
		MaxConnsPerHost:       50,
		IdleConnTimeout:       90 * time.Second,
		TLSHandshakeTimeout:   10 * time.Second,
		ExpectContinueTimeout: 1 * time.Second,
	}

	prodLogging := &loggingTransport{base: prodTransport}

	prodClient := httpclient.NewAuthClient(
		httpclient.AuthModeHMAC,
		"production-secret",
		httpclient.WithTransport(prodLogging),
		httpclient.WithTimeout(30*time.Second),
		httpclient.WithMaxBodySize(10*1024*1024), // 10MB
	)

	fmt.Println("  ✓ Production client ready")
	fmt.Println("    - High connection limits for performance")
	fmt.Println("    - Request logging for debugging")
	fmt.Println("    - Automatic HMAC authentication")
	fmt.Println("    - Body size limits for security")
	_ = prodClient

	// Summary
	fmt.Println("\n=== Summary ===")
	fmt.Println("✓ Transports can be chained for composable functionality")
	fmt.Println("✓ Use WithTransport() to customize the underlying transport chain")
	fmt.Println("✓ Order matters: outer transports wrap inner ones")
	fmt.Println("✓ Perfect for adding logging, metrics, rate limiting, etc.")

	fmt.Println("\n=== Transport Chain Pattern ===")
	fmt.Println("Common pattern:")
	fmt.Println("  Client → Auth → Logging → Metrics → Base Transport")
	fmt.Println("\nEach layer:")
	fmt.Println("  1. Does its own processing")
	fmt.Println("  2. Calls the next transport in the chain")
	fmt.Println("  3. Returns the response (or error)")

	fmt.Println("\n=== Use Cases ===")
	fmt.Println("- Logging: Log all requests/responses")
	fmt.Println("- Metrics: Track request counts, latencies")
	fmt.Println("- Rate Limiting: Throttle requests")
	fmt.Println("- Retry Logic: Automatic retries on failure")
	fmt.Println("- Authentication: Add auth headers (this package!)")
	fmt.Println("- Tracing: Distributed tracing headers")

	fmt.Println("\n=== All examples completed! ===")
}
