CREATE TABLE api_keys (
    id          TEXT PRIMARY KEY,
    key_hash    TEXT NOT NULL,
    hmac_key_id TEXT NOT NULL,
    principal   TEXT NOT NULL,
    roles       TEXT[] NOT NULL DEFAULT '{}',
    enabled     BOOLEAN NOT NULL DEFAULT TRUE,
    expires_at  TIMESTAMPTZ,
    created_at  TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    updated_at  TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

CREATE INDEX idx_api_keys_principal ON api_keys (principal);

CREATE TABLE api_keys_audit (
    audit_id    BIGSERIAL PRIMARY KEY,
    key_id      TEXT NOT NULL,
    action      TEXT NOT NULL,
    changed_by  TEXT,
    changed_at  TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    old_values  JSONB,
    new_values  JSONB
);
