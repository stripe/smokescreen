package smokescreen

import (
	"context"
	"io"
	"log/slog"
	"sync/atomic"
	"testing"
)

type countingHandler struct {
	slog.Handler
	calls *atomic.Uint64
}

func (h countingHandler) Handle(ctx context.Context, r slog.Record) error {
	h.calls.Add(1)
	return h.Handler.Handle(ctx, r)
}
func (h countingHandler) WithAttrs(a []slog.Attr) slog.Handler {
	return countingHandler{h.Handler.WithAttrs(a), h.calls}
}
func (h countingHandler) WithGroup(g string) slog.Handler {
	return countingHandler{h.Handler.WithGroup(g), h.calls}
}

func BenchmarkCallerHandler(b *testing.B) {
	var calls atomic.Uint64
	cfg := NewConfig()
	cfg.Log = slog.New(countingHandler{slog.NewJSONHandler(io.Discard, nil), &calls})
	pctx := canonicalFixture(cfg)
	b.ReportAllocs()
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		logProxy(pctx)
	}
	b.StopTimer()
	if got := calls.Load(); got != uint64(b.N) {
		b.Fatalf("got %d calls, want %d", got, b.N)
	}
}
