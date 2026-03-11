// Package memory provides an in-memory implementation of store.KeyManager
// for unit tests and development.
package memory

import (
	"context"
	"fmt"
	"sort"
	"sync"
	"time"

	"github.com/mai/pdag/internal/store"
)

// Compile-time interface checks.
var (
	_ store.KeyStore   = (*Store)(nil)
	_ store.KeyManager = (*Store)(nil)
)

// Store is an in-memory KeyManager for unit tests.
type Store struct {
	mu   sync.RWMutex
	keys map[string]*store.KeyRecord
}

func NewStore() *Store {
	return &Store{keys: make(map[string]*store.KeyRecord)}
}

func (m *Store) GetByID(_ context.Context, id string) (*store.KeyRecord, error) {
	m.mu.RLock()
	defer m.mu.RUnlock()
	rec, ok := m.keys[id]
	if !ok {
		return nil, nil
	}
	cp := *rec
	cp.Roles = make([]string, len(rec.Roles))
	copy(cp.Roles, rec.Roles)
	return &cp, nil
}

func (m *Store) Create(_ context.Context, rec *store.KeyRecord) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	if _, exists := m.keys[rec.ID]; exists {
		return fmt.Errorf("key %q already exists", rec.ID)
	}
	cp := *rec
	cp.Roles = make([]string, len(rec.Roles))
	copy(cp.Roles, rec.Roles)
	if cp.CreatedAt.IsZero() {
		cp.CreatedAt = time.Now()
	}
	cp.UpdatedAt = time.Now()
	m.keys[rec.ID] = &cp
	return nil
}

func (m *Store) List(_ context.Context) ([]*store.KeyRecord, error) {
	m.mu.RLock()
	defer m.mu.RUnlock()
	result := make([]*store.KeyRecord, 0, len(m.keys))
	for _, rec := range m.keys {
		cp := *rec
		cp.Roles = make([]string, len(rec.Roles))
		copy(cp.Roles, rec.Roles)
		result = append(result, &cp)
	}
	return result, nil
}

func (m *Store) ListPaged(_ context.Context, limit, offset int) ([]*store.KeyRecord, error) {
	m.mu.RLock()
	defer m.mu.RUnlock()

	// Collect and sort by CreatedAt for stable pagination.
	all := make([]*store.KeyRecord, 0, len(m.keys))
	for _, rec := range m.keys {
		all = append(all, rec)
	}
	sort.Slice(all, func(i, j int) bool {
		return all[i].CreatedAt.Before(all[j].CreatedAt)
	})

	// Apply offset.
	if offset >= len(all) {
		return nil, nil
	}
	all = all[offset:]

	// Apply limit.
	if limit < len(all) {
		all = all[:limit]
	}

	// Return copies.
	result := make([]*store.KeyRecord, len(all))
	for i, rec := range all {
		cp := *rec
		cp.Roles = make([]string, len(rec.Roles))
		copy(cp.Roles, rec.Roles)
		result[i] = &cp
	}
	return result, nil
}

func (m *Store) ListFiltered(_ context.Context, limit, offset int, principal, role string) ([]*store.KeyRecord, error) {
	m.mu.RLock()
	defer m.mu.RUnlock()

	// Collect matching records sorted by CreatedAt.
	all := make([]*store.KeyRecord, 0, len(m.keys))
	for _, rec := range m.keys {
		if principal != "" && rec.Principal != principal {
			continue
		}
		if role != "" {
			found := false
			for _, r := range rec.Roles {
				if r == role {
					found = true
					break
				}
			}
			if !found {
				continue
			}
		}
		all = append(all, rec)
	}
	sort.Slice(all, func(i, j int) bool {
		return all[i].CreatedAt.Before(all[j].CreatedAt)
	})

	if offset >= len(all) {
		return nil, nil
	}
	all = all[offset:]
	if limit < len(all) {
		all = all[:limit]
	}

	result := make([]*store.KeyRecord, len(all))
	for i, rec := range all {
		cp := *rec
		cp.Roles = make([]string, len(rec.Roles))
		copy(cp.Roles, rec.Roles)
		result[i] = &cp
	}
	return result, nil
}

func (m *Store) SetEnabled(_ context.Context, id string, enabled bool) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	rec, ok := m.keys[id]
	if !ok {
		return fmt.Errorf("key %q not found", id)
	}
	rec.Enabled = enabled
	rec.UpdatedAt = time.Now()
	return nil
}

func (m *Store) SetRoles(_ context.Context, id string, roles []string) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	rec, ok := m.keys[id]
	if !ok {
		return fmt.Errorf("key %q not found", id)
	}
	rec.Roles = make([]string, len(roles))
	copy(rec.Roles, roles)
	rec.UpdatedAt = time.Now()
	return nil
}

func (m *Store) UpdateHash(_ context.Context, id string, newHash string, newHmacKeyID string) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	rec, ok := m.keys[id]
	if !ok {
		return fmt.Errorf("key %q not found", id)
	}
	rec.KeyHash = newHash
	rec.HmacKeyID = newHmacKeyID
	rec.UpdatedAt = time.Now()
	return nil
}

func (m *Store) Delete(_ context.Context, id string) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	if _, ok := m.keys[id]; !ok {
		return fmt.Errorf("key %q not found", id)
	}
	delete(m.keys, id)
	return nil
}

func (m *Store) SetExpiresAt(_ context.Context, id string, expiresAt *time.Time) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	rec, ok := m.keys[id]
	if !ok {
		return fmt.Errorf("key %q not found", id)
	}
	if expiresAt != nil {
		t := *expiresAt
		rec.ExpiresAt = &t
	} else {
		rec.ExpiresAt = nil
	}
	rec.UpdatedAt = time.Now()
	return nil
}

func (m *Store) DeleteExpired(_ context.Context, before time.Time) (int64, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	var count int64
	for id, rec := range m.keys {
		if rec.ExpiresAt != nil && rec.ExpiresAt.Before(before) {
			delete(m.keys, id)
			count++
		}
	}
	return count, nil
}

func (m *Store) AuditKeyEvent(_ context.Context, _, _, _ string, _, _ any) error {
	return nil
}

func (m *Store) Close() error {
	return nil
}
