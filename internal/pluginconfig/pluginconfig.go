// Package pluginconfig stores plugin configurations with their secret
// fields encrypted, and turns stored configurations into live plugins.
//
// A plugin marks secret fields in its JSON Schema with "x-secret": true.
// On save, each such value is moved into the Vault and replaced by
// {"$secret": "<id>"}. Secrets are resolved only when a plugin instance is
// built inside the server; the API only ever shows them redacted.
package pluginconfig

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"strings"

	"github.com/tntrock/certower/internal/secrets"
	"github.com/tntrock/certower/internal/store"
	"github.com/tntrock/certower/pkg/plugin"
)

// Redacted replaces secret values in API responses.
const Redacted = "********"

const secretRef = "$secret"

// ErrInvalid wraps configuration errors the caller can fix.
var ErrInvalid = errors.New("invalid configuration")

// Service manages plugin configurations.
type Service struct {
	Store    *store.Store
	Vault    *secrets.Vault
	Registry *plugin.Registry
}

// CreateRequest describes a new configuration. Config carries secret values
// in plain text.
type CreateRequest struct {
	OrgID     string
	ProjectID string
	Kind      plugin.Kind
	Plugin    string
	Name      string
	Config    json.RawMessage
}

// Create validates the configuration by configuring a plugin instance with
// it, then stores it with secrets encrypted.
func (s *Service) Create(ctx context.Context, req CreateRequest) (*store.PluginConfig, error) {
	p, err := s.Registry.New(req.Kind, req.Plugin)
	if err != nil {
		return nil, fmt.Errorf("%w: %v", ErrInvalid, err)
	}
	raw := req.Config
	if len(raw) == 0 {
		raw = json.RawMessage(`{}`)
	}
	if len(secretIDs(raw)) > 0 {
		return nil, fmt.Errorf("%w: \"%s\" is reserved", ErrInvalid, secretRef)
	}
	if prep, ok := p.(plugin.ConfigPreparer); ok {
		if raw, err = prep.PrepareConfig(ctx, raw); err != nil {
			return nil, fmt.Errorf("%w: %v", ErrInvalid, err)
		}
	}
	if err := p.Configure(ctx, raw); err != nil {
		return nil, fmt.Errorf("%w: %v", ErrInvalid, err)
	}
	paths, err := secretPaths(p.Meta().ConfigSchema)
	if err != nil {
		return nil, err
	}
	var doc map[string]any
	if err := json.Unmarshal(raw, &doc); err != nil {
		return nil, fmt.Errorf("%w: %v", ErrInvalid, err)
	}

	id := store.NewID()
	var created *store.PluginConfig
	err = s.Store.InTx(ctx, func(tx *store.Store) error {
		vault := s.Vault.WithStore(tx)
		for _, path := range paths {
			parent, key, ok := lookup(doc, path)
			if !ok {
				continue
			}
			val, isStr := parent[key].(string)
			if !isStr || val == "" {
				continue
			}
			sid, err := vault.Put(ctx, req.OrgID, req.ProjectID, "config:"+id+":"+strings.Join(path, "."), []byte(val))
			if err != nil {
				return err
			}
			parent[key] = map[string]any{secretRef: sid}
		}
		sealed, err := json.Marshal(doc)
		if err != nil {
			return err
		}
		created, err = tx.CreatePluginConfig(ctx, store.PluginConfig{
			ID: id, OrgID: req.OrgID, ProjectID: req.ProjectID, Kind: string(req.Kind),
			Plugin: req.Plugin, Name: req.Name, Config: sealed,
		})
		return err
	})
	if err != nil {
		return nil, err
	}
	return created, nil
}

// Delete removes a configuration and its secrets. It fails with
// store.ErrInvalidReference while something still uses the configuration.
func (s *Service) Delete(ctx context.Context, pc *store.PluginConfig) error {
	return s.Store.InTx(ctx, func(tx *store.Store) error {
		if err := tx.DeletePluginConfig(ctx, pc.ID); err != nil {
			return err
		}
		vault := s.Vault.WithStore(tx)
		for _, id := range secretIDs(pc.Config) {
			if err := vault.Delete(ctx, id); err != nil && !errors.Is(err, store.ErrNotFound) {
				return err
			}
		}
		return nil
	})
}

// Instantiate builds a configured plugin from a stored configuration.
func (s *Service) Instantiate(ctx context.Context, pc *store.PluginConfig) (plugin.Plugin, error) {
	p, err := s.Registry.New(plugin.Kind(pc.Kind), pc.Plugin)
	if err != nil {
		return nil, err
	}
	var doc any
	if err := json.Unmarshal(pc.Config, &doc); err != nil {
		return nil, err
	}
	resolved, err := s.resolve(ctx, pc, doc)
	if err != nil {
		return nil, fmt.Errorf("config %q: %w", pc.Name, err)
	}
	raw, err := json.Marshal(resolved)
	if err != nil {
		return nil, err
	}
	if err := p.Configure(ctx, raw); err != nil {
		return nil, fmt.Errorf("config %q: %w", pc.Name, err)
	}
	return p, nil
}

func (s *Service) resolve(ctx context.Context, pc *store.PluginConfig, v any) (any, error) {
	switch t := v.(type) {
	case map[string]any:
		if id, ok := secretRefID(t); ok {
			val, err := s.Vault.GetScoped(ctx, id, pc.OrgID, pc.ProjectID)
			if err != nil {
				return nil, fmt.Errorf("secret %s: %w", id, err)
			}
			return string(val), nil
		}
		for k, child := range t {
			r, err := s.resolve(ctx, pc, child)
			if err != nil {
				return nil, err
			}
			t[k] = r
		}
	case []any:
		for i, child := range t {
			r, err := s.resolve(ctx, pc, child)
			if err != nil {
				return nil, err
			}
			t[i] = r
		}
	}
	return v, nil
}

// Redact returns a stored configuration with secret references shown as
// Redacted, for API responses.
func Redact(pc store.PluginConfig) store.PluginConfig {
	var doc any
	if json.Unmarshal(pc.Config, &doc) != nil {
		pc.Config = json.RawMessage(`{}`)
		return pc
	}
	pc.Config, _ = json.Marshal(redact(doc))
	return pc
}

func redact(v any) any {
	switch t := v.(type) {
	case map[string]any:
		if _, ok := secretRefID(t); ok {
			return Redacted
		}
		for k, child := range t {
			t[k] = redact(child)
		}
	case []any:
		for i, child := range t {
			t[i] = redact(child)
		}
	}
	return v
}

func secretRefID(m map[string]any) (string, bool) {
	if len(m) != 1 {
		return "", false
	}
	id, ok := m[secretRef].(string)
	return id, ok
}

func secretIDs(raw json.RawMessage) []string {
	var doc any
	if json.Unmarshal(raw, &doc) != nil {
		return nil
	}
	var out []string
	var walk func(any)
	walk = func(v any) {
		switch t := v.(type) {
		case map[string]any:
			if id, ok := secretRefID(t); ok {
				out = append(out, id)
				return
			}
			for _, c := range t {
				walk(c)
			}
		case []any:
			for _, c := range t {
				walk(c)
			}
		}
	}
	walk(doc)
	return out
}

// secretPaths lists the property paths a JSON Schema marks "x-secret".
// Only nested objects are followed; secrets inside arrays are not supported.
func secretPaths(schema json.RawMessage) ([][]string, error) {
	if len(schema) == 0 {
		return nil, nil
	}
	var root map[string]any
	if err := json.Unmarshal(schema, &root); err != nil {
		return nil, fmt.Errorf("plugin config schema: %w", err)
	}
	var out [][]string
	var walk func(node map[string]any, prefix []string)
	walk = func(node map[string]any, prefix []string) {
		props, _ := node["properties"].(map[string]any)
		for name, raw := range props {
			prop, ok := raw.(map[string]any)
			if !ok {
				continue
			}
			path := append(append([]string{}, prefix...), name)
			if secret, _ := prop["x-secret"].(bool); secret {
				out = append(out, path)
				continue
			}
			walk(prop, path)
		}
	}
	walk(root, nil)
	return out, nil
}

// lookup finds the map holding the last element of path.
func lookup(doc map[string]any, path []string) (map[string]any, string, bool) {
	cur := doc
	for _, p := range path[:len(path)-1] {
		next, ok := cur[p].(map[string]any)
		if !ok {
			return nil, "", false
		}
		cur = next
	}
	key := path[len(path)-1]
	_, ok := cur[key]
	return cur, key, ok
}
