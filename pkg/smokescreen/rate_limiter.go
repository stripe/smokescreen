package smokescreen

import (
	"math"
	"net/http"
	"sync"
	"sync/atomic"
	"time"
)

type rateLimiter struct {
	mu         sync.Mutex
	tokens     float64
	maxTokens  float64
	refillRate float64 // tokens per second
	lastRefill time.Time
}

type RateLimitedHandler struct {
	handler            http.Handler
	concurrencyLimiter chan struct{}
	rateLimiter        *rateLimiter
	config             *Config
}

func newRateLimiter(tokensPerSecond float64, burstCapacity int) *rateLimiter {
	burst := float64(burstCapacity)
	return &rateLimiter{
		tokens:     burst,
		maxTokens:  burst,
		refillRate: tokensPerSecond,
		lastRefill: time.Now(),
	}
}

func (rl *rateLimiter) Allow() bool {
	rl.mu.Lock()
	defer rl.mu.Unlock()

	// Refill tokens based on time elapsed
	now := time.Now()
	elapsed := now.Sub(rl.lastRefill).Seconds()
	rl.tokens = math.Min(rl.maxTokens, rl.tokens+elapsed*rl.refillRate)
	rl.lastRefill = now

	// Check if we have a token available
	if rl.tokens >= 1.0 {
		rl.tokens -= 1.0
		return true
	}

	return false
}

// NewRateLimitedHandler creates a new rate and concurrency limited handler
func NewRateLimitedHandler(handler http.Handler, config *Config) *RateLimitedHandler {
	var concurrencyLimiter chan struct{}
	if config.MaxConcurrentRequests > 0 {
		concurrencyLimiter = make(chan struct{}, config.MaxConcurrentRequests)
	}

	var rateLim *rateLimiter
	if config.MaxRequestRate > 0 {
		rateLim = newRateLimiter(config.MaxRequestRate, config.MaxRequestBurst)
	}

	return &RateLimitedHandler{
		handler:            handler,
		concurrencyLimiter: concurrencyLimiter,
		rateLimiter:        rateLim,
		config:             config,
	}
}

func (r *RateLimitedHandler) ServeHTTP(w http.ResponseWriter, req *http.Request) {
	if r.rateLimiter != nil && !r.rateLimiter.Allow() {
		r.config.MetricsClient.Incr("requests.rate_limited", 1)
		w.Header().Set("Retry-After", "1")
		http.Error(w, "Proxy rate limit exceeded. Please retry later.", http.StatusTooManyRequests)
		return
	}

	if r.concurrencyLimiter != nil {
		select {
		case r.concurrencyLimiter <- struct{}{}:
			defer func() { <-r.concurrencyLimiter }()
		default:
			r.config.MetricsClient.Incr("requests.concurrency_limited", 1)
			w.Header().Set("Retry-After", "1")
			http.Error(w, "Proxy overloaded. Please retry later.", http.StatusServiceUnavailable)
			return
		}
	}

	// Track concurrent requests for monitoring
	concurrent := atomic.AddInt64(&currentConcurrentRequests, 1)
	defer atomic.AddInt64(&currentConcurrentRequests, -1)
	if r.config.MetricsClient != nil && concurrent%10 == 0 {
		r.config.MetricsClient.Gauge("requests.concurrent", float64(concurrent), 1)
	}

	r.handler.ServeHTTP(w, req)
}

