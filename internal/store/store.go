package store

import (
	"context"
	"time"
)

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
	SetEnabled(ctx context.Context, id string, enabled bool) error
	SetRoles(ctx context.Context, id string, roles []string) error
	UpdateHash(ctx context.Context, id string, newHash string, newHmacKeyID string) error
	Delete(ctx context.Context, id string) error
	AuditKeyEvent(ctx context.Context, keyID, action, changedBy string, oldValues, newValues any) error
}
