package store

import (
	"context"
	"errors"
	"time"
)

// ErrKeyNotFound is returned when a key mutation targets a non-existent key ID.
var ErrKeyNotFound = errors.New("key not found")

type KeyRecord struct {
	ID        string
	KeyHash   string
	HmacKeyID string
	Principal string
	Roles     []string
	Enabled   bool
	ExpiresAt *time.Time
	CreatedAt time.Time
	UpdatedAt time.Time
}

// KeyStore is the read-only interface used by the authn middleware on the hot path.
type KeyStore interface {
	GetByID(ctx context.Context, id string) (*KeyRecord, error)
	Close() error
}

// KeyManager extends KeyStore with write operations for the CLI and Admin API.
type KeyManager interface {
	KeyStore
	Create(ctx context.Context, rec *KeyRecord) error
	List(ctx context.Context) ([]*KeyRecord, error)
	ListPaged(ctx context.Context, limit, offset int) ([]*KeyRecord, error)
	ListFiltered(ctx context.Context, limit, offset int, principal, role string) ([]*KeyRecord, error)
	SetEnabled(ctx context.Context, id string, enabled bool) error
	SetRoles(ctx context.Context, id string, roles []string) error
	UpdateHash(ctx context.Context, id string, newHash string, newHmacKeyID string) error
	Delete(ctx context.Context, id string) error
	DeleteExpired(ctx context.Context, before time.Time) (int64, error)
	SetExpiresAt(ctx context.Context, id string, expiresAt *time.Time) error
	AuditKeyEvent(ctx context.Context, keyID, action, changedBy string, oldValues, newValues any) error
}
