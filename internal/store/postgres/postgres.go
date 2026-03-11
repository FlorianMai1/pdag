// Package postgres provides a PostgreSQL-backed implementation of store.KeyManager.
package postgres

import (
	"context"
	"database/sql"
	"encoding/json"
	"fmt"
	"time"

	"github.com/golang-migrate/migrate/v4"
	migratepg "github.com/golang-migrate/migrate/v4/database/postgres"
	_ "github.com/golang-migrate/migrate/v4/source/file"
	_ "github.com/jackc/pgx/v5/stdlib"

	"github.com/mai/pdag/internal/store"
)

// Compile-time interface checks.
var (
	_ store.KeyStore   = (*Store)(nil)
	_ store.KeyManager = (*Store)(nil)
)

// Store implements store.KeyManager backed by PostgreSQL.
type Store struct {
	db *sql.DB
}

// NewStore opens a connection to PostgreSQL and runs migrations.
func NewStore(dsn string, migrationsPath string) (*Store, error) {
	db, err := sql.Open("pgx", dsn)
	if err != nil {
		return nil, fmt.Errorf("open db: %w", err)
	}
	db.SetMaxOpenConns(25)
	db.SetMaxIdleConns(5)
	db.SetConnMaxLifetime(5 * time.Minute)

	if err := db.Ping(); err != nil {
		db.Close()
		return nil, fmt.Errorf("ping: %w", err)
	}

	if migrationsPath != "" {
		if err := runMigrations(db, migrationsPath); err != nil {
			db.Close()
			return nil, fmt.Errorf("migrations: %w", err)
		}
	}

	return &Store{db: db}, nil
}

func runMigrations(db *sql.DB, path string) error {
	driver, err := migratepg.WithInstance(db, &migratepg.Config{})
	if err != nil {
		return err
	}
	m, err := migrate.NewWithDatabaseInstance("file://"+path, "postgres", driver)
	if err != nil {
		return err
	}
	if err := m.Up(); err != nil && err != migrate.ErrNoChange {
		return err
	}
	return nil
}

func (s *Store) GetByID(ctx context.Context, id string) (*store.KeyRecord, error) {
	row := s.db.QueryRowContext(ctx,
		`SELECT id, key_hash, hmac_key_id, principal, roles, enabled, expires_at, created_at, updated_at
		 FROM api_keys WHERE id = $1`, id)

	rec := &store.KeyRecord{}
	var expiresAt sql.NullTime
	var roles TextArray
	err := row.Scan(
		&rec.ID, &rec.KeyHash, &rec.HmacKeyID, &rec.Principal,
		&roles, &rec.Enabled, &expiresAt,
		&rec.CreatedAt, &rec.UpdatedAt,
	)
	if err == sql.ErrNoRows {
		return nil, nil
	}
	if err != nil {
		return nil, fmt.Errorf("get key %q: %w", id, err)
	}
	rec.Roles = []string(roles)
	if expiresAt.Valid {
		rec.ExpiresAt = &expiresAt.Time
	}
	return rec, nil
}

func (s *Store) Create(ctx context.Context, rec *store.KeyRecord) error {
	_, err := s.db.ExecContext(ctx,
		`INSERT INTO api_keys (id, key_hash, hmac_key_id, principal, roles, enabled, expires_at)
		 VALUES ($1, $2, $3, $4, $5, $6, $7)`,
		rec.ID, rec.KeyHash, rec.HmacKeyID, rec.Principal,
		TextArray(rec.Roles), rec.Enabled, rec.ExpiresAt,
	)
	if err != nil {
		return fmt.Errorf("create key %q: %w", rec.ID, err)
	}
	return nil
}

func (s *Store) List(ctx context.Context) ([]*store.KeyRecord, error) {
	rows, err := s.db.QueryContext(ctx,
		`SELECT id, key_hash, hmac_key_id, principal, roles, enabled, expires_at, created_at, updated_at
		 FROM api_keys ORDER BY created_at`)
	if err != nil {
		return nil, fmt.Errorf("list keys: %w", err)
	}
	defer rows.Close()

	var result []*store.KeyRecord
	for rows.Next() {
		rec := &store.KeyRecord{}
		var expiresAt sql.NullTime
		var roles TextArray
		if err := rows.Scan(
			&rec.ID, &rec.KeyHash, &rec.HmacKeyID, &rec.Principal,
			&roles, &rec.Enabled, &expiresAt,
			&rec.CreatedAt, &rec.UpdatedAt,
		); err != nil {
			return nil, fmt.Errorf("scan key: %w", err)
		}
		rec.Roles = []string(roles)
		if expiresAt.Valid {
			rec.ExpiresAt = &expiresAt.Time
		}
		result = append(result, rec)
	}
	return result, rows.Err()
}

func (s *Store) ListPaged(ctx context.Context, limit, offset int) ([]*store.KeyRecord, error) {
	rows, err := s.db.QueryContext(ctx,
		`SELECT id, key_hash, hmac_key_id, principal, roles, enabled, expires_at, created_at, updated_at
		 FROM api_keys ORDER BY created_at LIMIT $1 OFFSET $2`, limit, offset)
	if err != nil {
		return nil, fmt.Errorf("list keys paged: %w", err)
	}
	defer rows.Close()

	var result []*store.KeyRecord
	for rows.Next() {
		rec := &store.KeyRecord{}
		var expiresAt sql.NullTime
		var roles TextArray
		if err := rows.Scan(
			&rec.ID, &rec.KeyHash, &rec.HmacKeyID, &rec.Principal,
			&roles, &rec.Enabled, &expiresAt,
			&rec.CreatedAt, &rec.UpdatedAt,
		); err != nil {
			return nil, fmt.Errorf("scan key: %w", err)
		}
		rec.Roles = []string(roles)
		if expiresAt.Valid {
			rec.ExpiresAt = &expiresAt.Time
		}
		result = append(result, rec)
	}
	return result, rows.Err()
}

func (s *Store) SetEnabled(ctx context.Context, id string, enabled bool) error {
	res, err := s.db.ExecContext(ctx,
		`UPDATE api_keys SET enabled = $1, updated_at = NOW() WHERE id = $2`,
		enabled, id)
	if err != nil {
		return fmt.Errorf("set enabled %q: %w", id, err)
	}
	return checkRowsAffected(res, id)
}

func (s *Store) SetRoles(ctx context.Context, id string, roles []string) error {
	res, err := s.db.ExecContext(ctx,
		`UPDATE api_keys SET roles = $1, updated_at = NOW() WHERE id = $2`,
		TextArray(roles), id)
	if err != nil {
		return fmt.Errorf("set roles %q: %w", id, err)
	}
	return checkRowsAffected(res, id)
}

func (s *Store) UpdateHash(ctx context.Context, id string, newHash string, newHmacKeyID string) error {
	res, err := s.db.ExecContext(ctx,
		`UPDATE api_keys SET key_hash = $1, hmac_key_id = $2, updated_at = NOW() WHERE id = $3`,
		newHash, newHmacKeyID, id)
	if err != nil {
		return fmt.Errorf("update hash %q: %w", id, err)
	}
	return checkRowsAffected(res, id)
}

func (s *Store) Delete(ctx context.Context, id string) error {
	res, err := s.db.ExecContext(ctx,
		`DELETE FROM api_keys WHERE id = $1`, id)
	if err != nil {
		return fmt.Errorf("delete key %q: %w", id, err)
	}
	return checkRowsAffected(res, id)
}

func (s *Store) DeleteExpired(ctx context.Context, before time.Time) (int64, error) {
	res, err := s.db.ExecContext(ctx,
		`DELETE FROM api_keys WHERE expires_at IS NOT NULL AND expires_at < $1`, before)
	if err != nil {
		return 0, fmt.Errorf("delete expired keys: %w", err)
	}
	n, err := res.RowsAffected()
	if err != nil {
		return 0, fmt.Errorf("delete expired rows affected: %w", err)
	}
	return n, nil
}

func (s *Store) AuditKeyEvent(ctx context.Context, keyID, action, changedBy string, oldValues, newValues any) error {
	oldJSON, err := json.Marshal(oldValues)
	if err != nil {
		return fmt.Errorf("marshal old values: %w", err)
	}
	newJSON, err := json.Marshal(newValues)
	if err != nil {
		return fmt.Errorf("marshal new values: %w", err)
	}
	_, err = s.db.ExecContext(ctx,
		`INSERT INTO api_keys_audit (key_id, action, changed_by, old_values, new_values)
		 VALUES ($1, $2, $3, $4, $5)`,
		keyID, action, changedBy, oldJSON, newJSON,
	)
	if err != nil {
		return fmt.Errorf("audit key event: %w", err)
	}
	return nil
}

func (s *Store) Close() error {
	return s.db.Close()
}

func checkRowsAffected(res sql.Result, id string) error {
	n, err := res.RowsAffected()
	if err != nil {
		return err
	}
	if n == 0 {
		return fmt.Errorf("key %q not found", id)
	}
	return nil
}
