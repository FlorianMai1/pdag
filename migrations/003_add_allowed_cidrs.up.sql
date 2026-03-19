ALTER TABLE api_keys ADD COLUMN allowed_cidrs TEXT[] NOT NULL DEFAULT '{}';
