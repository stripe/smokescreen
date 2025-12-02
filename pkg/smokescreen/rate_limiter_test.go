package smokescreen

import (
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stripe/smokescreen/pkg/smokescreen/metrics"
)

func TestRateLimiter(t *testing.T) {
	rl := newRateLimiter(10, 0) // 10 req/sec, burst 20

	// First 20 requests should be allowed (burst)
	for i := 0; i < 20; i++ {
		assert.True(t, rl.Allow())
	}

	// Next request should be denied
	assert.False(t, rl.Allow())

	// After waiting, should be allowed again
	time.Sleep(150 * time.Millisecond)
	assert.True(t, rl.Allow())
}

func TestRateLimiter_CustomBurst(t *testing.T) {
	rl := newRateLimiter(10, 50) // 10 req/sec, custom burst 50

	// First 50 requests should be allowed (custom burst)
	for i := 0; i < 50; i++ {
		assert.True(t, rl.Allow())
	}

	// Next request should be denied
	assert.False(t, rl.Allow())
}

func TestRateLimitedHandler_RateLimit(t *testing.T) {
	config := &Config{
		MaxConcurrentRequests: 0, // disabled
		MaxRequestRate:        5, // burst = 10
		MetricsClient:         metrics.NewNoOpMetricsClient(),
	}

	handler := NewRateLimitedHandler(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
	}), config)

	// First 10 requests pass (burst)
	for i := 0; i < 10; i++ {
		w := httptest.NewRecorder()
		handler.ServeHTTP(w, httptest.NewRequest("GET", "/", nil))
		assert.Equal(t, http.StatusOK, w.Code)
	}

	// 11th request gets rate limited with Retry-After header
	w := httptest.NewRecorder()
	handler.ServeHTTP(w, httptest.NewRequest("GET", "/", nil))
	assert.Equal(t, http.StatusTooManyRequests, w.Code)
	assert.Equal(t, "1", w.Header().Get("Retry-After"))
}

func TestRateLimitedHandler_Concurrency(t *testing.T) {
	config := &Config{
		MaxConcurrentRequests: 1, // only 1 concurrent
		MaxRequestRate:        0, // disabled
		MetricsClient:         metrics.NewNoOpMetricsClient(),
	}

	blocked := make(chan struct{})
	release := make(chan struct{})

	handler := NewRateLimitedHandler(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		blocked <- struct{}{} // signal we're in handler
		<-release            // wait for release
		w.WriteHeader(http.StatusOK)
	}), config)

	// Start first request (will block in handler)
	go func() {
		w := httptest.NewRecorder()
		handler.ServeHTTP(w, httptest.NewRequest("GET", "/", nil))
	}()

	<-blocked // wait for first request to enter handler

	// Second request should get 503 with Retry-After header
	w := httptest.NewRecorder()
	handler.ServeHTTP(w, httptest.NewRequest("GET", "/", nil))
	assert.Equal(t, http.StatusServiceUnavailable, w.Code)
	assert.Equal(t, "1", w.Header().Get("Retry-After"))

	release <- struct{}{} // cleanup
}
