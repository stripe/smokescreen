package testlog

import (
	"log/slog"
	"testing"
	"testing/slogtest"
)

func TestHandler(t *testing.T) {
	h := &Handler{}
	if err := slogtest.TestHandler(h, func() []map[string]any {
		var result []map[string]any
		for _, e := range h.AllEntries() {
			data := map[string]any{}
			for k, v := range e.Data {
				data[k] = v
			}
			if !e.Time.IsZero() {
				data[slog.TimeKey] = e.Time
			}
			data[slog.LevelKey] = e.Level
			data[slog.MessageKey] = e.Message
			result = append(result, data)
		}
		return result
	}); err != nil {
		t.Fatal(err)
	}
}
