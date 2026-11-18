package goproxy

import (
	"io"
	"sync"
	"sync/atomic"
)

// HTTPRequestStats contains estimated payload counts, excluding headers,
// framing, and TLS overhead. WriterTo paths count bytes written; transfer errors
// may originate from either peer.
type HTTPRequestStats struct {
	// BytesIn counts response payload before response filters.
	BytesIn int64
	// BytesOut counts request payload after request filters, including retries.
	BytesOut int64
	// Error is a forwarding or body-transfer error, if any.
	Error error
}

type httpRequestCompletion struct {
	mu           sync.Mutex
	handler      func(*ProxyCtx, HTTPRequestStats)
	ctx          *ProxyCtx
	stats        HTTPRequestStats
	responseBody *httpResponseBodyCounter
	pending      int
	finished     bool
	reported     bool
}

// notifyLocked snapshots the result before releasing the lock. Callers invoke
// the returned closure without holding the lock, allowing arbitrary callbacks.
func (c *httpRequestCompletion) notifyLocked() func() {
	if !c.finished || c.pending != 0 || c.reported {
		return func() {}
	}
	c.reported = true
	if c.responseBody != nil {
		c.stats.BytesIn = atomic.LoadInt64(&c.responseBody.bytesRead)
	}
	stats := c.stats
	return func() { c.handler(c.ctx, stats) }
}

func (c *httpRequestCompletion) finish(err error, responseBody *httpResponseBodyCounter) {
	c.mu.Lock()
	c.responseBody = responseBody
	c.finished = true
	if err != nil {
		c.stats.Error = err
	}
	notify := c.notifyLocked()
	c.mu.Unlock()
	notify()
}

func (c *httpRequestCompletion) requestBody(body io.ReadCloser) io.ReadCloser {
	c.mu.Lock()
	c.pending++
	c.mu.Unlock()
	counter := &httpRequestBodyCounter{body: body, completion: c}
	if writerTo, ok := body.(io.WriterTo); ok {
		return &httpRequestBodyWriterTo{httpRequestBodyCounter: counter, writerTo: writerTo}
	}
	return counter
}

type httpRequestBodyCounter struct {
	body       io.ReadCloser
	completion *httpRequestCompletion
	closeOnce  sync.Once
	closeErr   error
	// Guarded by completion.mu. Close may run concurrently with Read.
	active   int
	closed   bool
	released bool
}

func (b *httpRequestBodyCounter) releaseLocked() {
	if b.closed && b.active == 0 && !b.released {
		b.released = true
		b.completion.pending--
	}
}

func (b *httpRequestBodyCounter) Read(p []byte) (int, error) {
	c := b.completion
	c.mu.Lock()
	if b.closed {
		c.mu.Unlock()
		return 0, io.ErrClosedPipe
	}
	b.active++
	c.mu.Unlock()

	n, err := b.body.Read(p)
	c.mu.Lock()
	c.stats.BytesOut += int64(n)
	if err != nil && err != io.EOF && c.stats.Error == nil {
		c.stats.Error = err
	}
	b.active--
	b.releaseLocked()
	notify := c.notifyLocked()
	c.mu.Unlock()
	notify()
	return n, err
}

func (b *httpRequestBodyCounter) Close() error {
	b.closeOnce.Do(func() {
		b.closeErr = b.body.Close()
		c := b.completion
		c.mu.Lock()
		b.closed = true
		b.releaseLocked()
		c.mu.Unlock()
	})
	// Invoke outside sync.Once as the callback may itself close the body.
	c := b.completion
	c.mu.Lock()
	notify := c.notifyLocked()
	c.mu.Unlock()
	notify()
	return b.closeErr
}

type httpRequestBodyWriterTo struct {
	*httpRequestBodyCounter
	writerTo io.WriterTo
}

func (b *httpRequestBodyWriterTo) WriteTo(w io.Writer) (int64, error) {
	c := b.completion
	c.mu.Lock()
	if b.closed {
		c.mu.Unlock()
		return 0, io.ErrClosedPipe
	}
	b.active++
	c.mu.Unlock()

	n, err := b.writerTo.WriteTo(w)
	c.mu.Lock()
	c.stats.BytesOut += n
	if err != nil && err != io.EOF && c.stats.Error == nil {
		c.stats.Error = err
	}
	b.active--
	b.releaseLocked()
	notify := c.notifyLocked()
	c.mu.Unlock()
	notify()
	return n, err
}

type httpResponseBodyCounter struct {
	// Keep the 64-bit atomic first for alignment on 32-bit architectures.
	bytesRead int64
	io.ReadCloser
	completion *httpRequestCompletion
}

func (b *httpResponseBodyCounter) Read(p []byte) (int, error) {
	n, err := b.ReadCloser.Read(p)
	b.account(int64(n), err)
	return n, err
}

// account keeps the successful response path lock-free. For non-EOF errors,
// bytes and the error are published together under completion.mu so a final
// snapshot cannot observe one without the other.
func (b *httpResponseBodyCounter) account(n int64, err error) {
	if err != nil && err != io.EOF {
		c := b.completion
		c.mu.Lock()
		if n != 0 {
			atomic.AddInt64(&b.bytesRead, n)
		}
		if c.stats.Error == nil {
			c.stats.Error = err
		}
		c.mu.Unlock()
		return
	}
	if n != 0 {
		atomic.AddInt64(&b.bytesRead, n)
	}
}

type httpResponseBodyWriterTo struct {
	*httpResponseBodyCounter
	writerTo io.WriterTo
}

func (b *httpResponseBodyWriterTo) WriteTo(w io.Writer) (int64, error) {
	n, err := b.writerTo.WriteTo(w)
	b.account(n, err)
	return n, err
}
