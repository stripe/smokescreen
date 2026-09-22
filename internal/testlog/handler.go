// Package testlog records structured logs for tests. It is not a logging backend
// shipped by Smokescreen or a compatibility layer for integrations.
package testlog

import (
	"context"
	"log/slog"
	"sync"
)

type Entry struct {
	slog.Record
	Data    map[string]any
	Context context.Context
}
type state struct {
	sync.Mutex
	entries         []*Entry
	enabledContexts []context.Context
}
type scopedAttrs struct {
	groups []string
	attrs  []slog.Attr
}

// Handler supports the zero value. Derived handlers share synchronized storage.
type Handler struct {
	once   sync.Once
	state  *state
	groups []string
	bound  []scopedAttrs
	Level  slog.Leveler
}

func (h *Handler) init() *state {
	h.once.Do(func() {
		if h.state == nil {
			h.state = &state{}
		}
	})
	return h.state
}
func (h *Handler) Enabled(ctx context.Context, level slog.Level) bool {
	s := h.init()
	s.Lock()
	s.enabledContexts = append(s.enabledContexts, ctx)
	s.Unlock()
	return h.Level == nil || level >= h.Level.Level()
}
func resolve(attrs []slog.Attr) []slog.Attr {
	result := make([]slog.Attr, 0, len(attrs))
	for _, a := range attrs {
		a.Value = a.Value.Resolve()
		if a.Value.Kind() == slog.KindGroup {
			a.Value = slog.GroupValue(resolve(a.Value.Group())...)
		}
		result = append(result, a)
	}
	return result
}
func add(data map[string]any, groups []string, attrs []slog.Attr) {
	for _, a := range attrs {
		if a.Equal(slog.Attr{}) {
			continue
		}
		if a.Value.Kind() == slog.KindGroup && len(a.Value.Group()) == 0 {
			continue
		}
		target := data
		for _, group := range groups {
			next, ok := target[group].(map[string]any)
			if !ok {
				next = map[string]any{}
				target[group] = next
			}
			target = next
		}
		if a.Value.Kind() == slog.KindGroup {
			if a.Key == "" {
				add(target, nil, a.Value.Group())
			} else {
				add(target, []string{a.Key}, a.Value.Group())
			}
		} else {
			target[a.Key] = a.Value.Any()
		}
	}
}
func (h *Handler) Handle(ctx context.Context, r slog.Record) error {
	data := map[string]any{}
	for _, bound := range h.bound {
		add(data, bound.groups, bound.attrs)
	}
	attrs := []slog.Attr{}
	r.Attrs(func(a slog.Attr) bool { attrs = append(attrs, a); return true })
	add(data, h.groups, resolve(attrs))
	s := h.init()
	s.Lock()
	defer s.Unlock()
	s.entries = append(s.entries, &Entry{Record: r.Clone(), Data: data, Context: ctx})
	return nil
}
func (h *Handler) WithAttrs(attrs []slog.Attr) slog.Handler {
	bound := append([]scopedAttrs(nil), h.bound...)
	bound = append(bound, scopedAttrs{append([]string(nil), h.groups...), resolve(attrs)})
	return &Handler{state: h.init(), groups: append([]string(nil), h.groups...), bound: bound, Level: h.Level}
}
func (h *Handler) WithGroup(name string) slog.Handler {
	if name == "" {
		return h
	}
	return &Handler{state: h.init(), groups: append(append([]string(nil), h.groups...), name), bound: h.bound, Level: h.Level}
}
func (h *Handler) AllEntries() []*Entry {
	s := h.init()
	s.Lock()
	defer s.Unlock()
	return append([]*Entry(nil), s.entries...)
}
func (h *Handler) LastEntry() *Entry {
	entries := h.AllEntries()
	if len(entries) == 0 {
		return nil
	}
	return entries[len(entries)-1]
}
func (h *Handler) Reset() {
	s := h.init()
	s.Lock()
	defer s.Unlock()
	s.entries = nil
	s.enabledContexts = nil
}
func (h *Handler) EnabledContexts() []context.Context {
	s := h.init()
	s.Lock()
	defer s.Unlock()
	return append([]context.Context(nil), s.enabledContexts...)
}
func New() (*slog.Logger, *Handler) { h := &Handler{}; return slog.New(h), h }
