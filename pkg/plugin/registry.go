package plugin

import (
	"fmt"
	"sort"
	"sync"
)

// Factory creates a fresh, unconfigured plugin instance.
type Factory func() Plugin

// Registry holds plugin factories by kind and name.
type Registry struct {
	mu        sync.RWMutex
	factories map[Kind]map[string]Factory
}

// NewRegistry returns an empty registry.
func NewRegistry() *Registry {
	return &Registry{factories: map[Kind]map[string]Factory{}}
}

// Default is the registry built-in plugins register with.
var Default = NewRegistry()

// Register adds a factory. It panics on duplicates, since registration
// happens at init time and a duplicate is a programming error.
func (r *Registry) Register(f Factory) {
	m := f().Meta()
	if m.Name == "" || m.Kind == "" {
		panic("plugin: Meta must set Name and Kind")
	}
	r.mu.Lock()
	defer r.mu.Unlock()
	byName := r.factories[m.Kind]
	if byName == nil {
		byName = map[string]Factory{}
		r.factories[m.Kind] = byName
	}
	if _, dup := byName[m.Name]; dup {
		panic(fmt.Sprintf("plugin: %s %q registered twice", m.Kind, m.Name))
	}
	byName[m.Name] = f
}

// New creates an instance of the named plugin.
func (r *Registry) New(kind Kind, name string) (Plugin, error) {
	r.mu.RLock()
	f, ok := r.factories[kind][name]
	r.mu.RUnlock()
	if !ok {
		return nil, fmt.Errorf("plugin: no %s plugin named %q", kind, name)
	}
	return f(), nil
}

// List returns the metadata of all plugins of a kind, sorted by name.
func (r *Registry) List(kind Kind) []Meta {
	r.mu.RLock()
	defer r.mu.RUnlock()
	out := make([]Meta, 0, len(r.factories[kind]))
	for _, f := range r.factories[kind] {
		out = append(out, f().Meta())
	}
	sort.Slice(out, func(i, j int) bool { return out[i].Name < out[j].Name })
	return out
}
