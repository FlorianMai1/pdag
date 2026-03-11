package config

import (
	"os"
	"path/filepath"
	"testing"
	"time"
)

func TestLoadFromYAML(t *testing.T) {
	dir := t.TempDir()
	cfgFile := filepath.Join(dir, "pdag.yaml")
	err := os.WriteFile(cfgFile, []byte(`
upstreams:
  backends:
    - url: "http://pdns:8081"
      api_key: "test-key"
listen: ":9999"
max_body_size: 2048
audit_log: "/tmp/audit.jsonl"
hmac_secrets:
  - id: "v1"
    secret: "my-secret-that-is-long-enough"
db:
  driver: "postgres"
  dsn: "postgres://localhost/test"
`), 0644)
	if err != nil {
		t.Fatal(err)
	}

	cfg, err := Load(cfgFile)
	if err != nil {
		t.Fatal(err)
	}

	if cfg.Upstreams.Backends[0].URL != "http://pdns:8081" {
		t.Errorf("backend[0].url = %q, want %q", cfg.Upstreams.Backends[0].URL, "http://pdns:8081")
	}
	if cfg.Upstreams.Backends[0].APIKey != "test-key" {
		t.Errorf("backend[0].api_key = %q, want %q", cfg.Upstreams.Backends[0].APIKey, "test-key")
	}
	if cfg.Listen != ":9999" {
		t.Errorf("listen = %q, want %q", cfg.Listen, ":9999")
	}
	if cfg.MaxBodySize != 2048 {
		t.Errorf("max_body_size = %d, want %d", cfg.MaxBodySize, 2048)
	}
	if cfg.AuditLog != "/tmp/audit.jsonl" {
		t.Errorf("audit_log = %q, want %q", cfg.AuditLog, "/tmp/audit.jsonl")
	}
	if cfg.DB.Driver != "postgres" {
		t.Errorf("db.driver = %q, want %q", cfg.DB.Driver, "postgres")
	}
	if len(cfg.HmacSecrets) != 1 || cfg.HmacSecrets[0].ID != "v1" {
		t.Errorf("hmac_secrets = %+v, want [{v1 my-secret}]", cfg.HmacSecrets)
	}
}

func TestLoadDefaults(t *testing.T) {
	dir := t.TempDir()
	cfgFile := filepath.Join(dir, "pdag.yaml")
	os.WriteFile(cfgFile, []byte(`
upstreams:
  backends:
    - url: "http://localhost:8081"
      api_key: "key"
hmac_secrets:
  - id: "v1"
    secret: "test-secret-long-enough"
db:
  driver: postgres
  dsn: "postgres://localhost/test"
`), 0644)

	cfg, err := Load(cfgFile)
	if err != nil {
		t.Fatal(err)
	}

	if cfg.Listen != ":8080" {
		t.Errorf("default listen = %q, want %q", cfg.Listen, ":8080")
	}
	if cfg.MaxBodySize != 1<<20 {
		t.Errorf("default max_body_size = %d, want %d", cfg.MaxBodySize, 1<<20)
	}
	if cfg.Metrics.Listen != ":9090" {
		t.Errorf("default metrics.listen = %q, want %q", cfg.Metrics.Listen, ":9090")
	}
	if cfg.PluginDefaults.Timeout != 500*time.Millisecond {
		t.Errorf("default plugin timeout = %v, want 500ms", cfg.PluginDefaults.Timeout)
	}
}

func TestLoadEnvOverride(t *testing.T) {
	dir := t.TempDir()
	cfgFile := filepath.Join(dir, "pdag.yaml")
	err := os.WriteFile(cfgFile, []byte(`
upstreams:
  backends:
    - url: "http://from-file:8081"
      api_key: "file-key"
listen: ":1111"
hmac_secrets:
  - id: "v1"
    secret: "test-secret-long-enough"
db:
  dsn: "postgres://localhost/test"
`), 0644)
	if err != nil {
		t.Fatal(err)
	}

	t.Setenv("PDAG_LISTEN", ":2222")

	cfg, err := Load(cfgFile)
	if err != nil {
		t.Fatal(err)
	}

	if cfg.Listen != ":2222" {
		t.Errorf("listen = %q, want env override %q", cfg.Listen, ":2222")
	}
	if cfg.Upstreams.Backends[0].URL != "http://from-file:8081" {
		t.Errorf("backend[0].url = %q, want %q", cfg.Upstreams.Backends[0].URL, "http://from-file:8081")
	}
}

func TestValidationMissingUpstream(t *testing.T) {
	dir := t.TempDir()
	cfgFile := filepath.Join(dir, "pdag.yaml")
	os.WriteFile(cfgFile, []byte(`listen: ":8080"`), 0644)

	_, err := Load(cfgFile)
	if err == nil {
		t.Fatal("expected validation error for missing upstreams")
	}
}

func TestLoadUpstreamsMultiBackend(t *testing.T) {
	dir := t.TempDir()
	cfgFile := filepath.Join(dir, "pdag.yaml")
	os.WriteFile(cfgFile, []byte(`
upstreams:
  backends:
    - url: "http://pdns-1:8081"
      api_key: "key-1"
    - url: "http://pdns-2:8081"
      api_key: "key-2"
  health_check:
    interval: 5s
    timeout: 1s
hmac_secrets:
  - id: "v1"
    secret: "test-secret-long-enough"
db:
  dsn: "postgres://localhost/test"
`), 0644)

	cfg, err := Load(cfgFile)
	if err != nil {
		t.Fatal(err)
	}

	if len(cfg.Upstreams.Backends) != 2 {
		t.Fatalf("backends = %d, want 2", len(cfg.Upstreams.Backends))
	}
	if cfg.Upstreams.Backends[0].URL != "http://pdns-1:8081" {
		t.Errorf("backend[0].url = %q, want http://pdns-1:8081", cfg.Upstreams.Backends[0].URL)
	}
	if cfg.Upstreams.Backends[1].APIKey != "key-2" {
		t.Errorf("backend[1].api_key = %q, want key-2", cfg.Upstreams.Backends[1].APIKey)
	}
	if cfg.Upstreams.HealthCheck.Interval != 5*time.Second {
		t.Errorf("health_check.interval = %v, want 5s", cfg.Upstreams.HealthCheck.Interval)
	}
}

// validBaseConfig returns a minimal valid YAML config for tests that need
// to test a single validation rule without tripping others.
func validBaseConfig(extra string) string {
	return `
upstreams:
  backends:
    - url: "http://pdns:8081"
      api_key: "key"
hmac_secrets:
  - id: "v1"
    secret: "test-secret-long-enough"
db:
  dsn: "postgres://localhost/test"
` + extra
}

func writeConfig(t *testing.T, content string) string {
	t.Helper()
	dir := t.TempDir()
	cfgFile := filepath.Join(dir, "pdag.yaml")
	os.WriteFile(cfgFile, []byte(content), 0644)
	return cfgFile
}

func TestValidateInvalidListenAddress(t *testing.T) {
	cfgFile := writeConfig(t, validBaseConfig(`listen: "not-a-valid-addr"`))
	_, err := Load(cfgFile)
	if err == nil {
		t.Fatal("expected error for invalid listen address")
	}
}

func TestValidateMaxBodySizeZero(t *testing.T) {
	cfgFile := writeConfig(t, validBaseConfig(`max_body_size: 0`))
	_, err := Load(cfgFile)
	if err == nil {
		t.Fatal("expected error for max_body_size=0")
	}
}

func TestValidateHmacSecretTooShort(t *testing.T) {
	cfg := `
upstreams:
  backends:
    - url: "http://pdns:8081"
      api_key: "key"
hmac_secrets:
  - id: "v1"
    secret: "short"
db:
  dsn: "postgres://localhost/test"
`
	cfgFile := writeConfig(t, cfg)
	_, err := Load(cfgFile)
	if err == nil {
		t.Fatal("expected error for short HMAC secret")
	}
}

func TestValidateRateLimitEnabled(t *testing.T) {
	cfg := validBaseConfig(`
rate_limit:
  enabled: true
  rate: 0
  burst: 10
`)
	cfgFile := writeConfig(t, cfg)
	_, err := Load(cfgFile)
	if err == nil {
		t.Fatal("expected error for rate=0 when enabled")
	}
}

func TestValidateHealthCheckTimeoutGEInterval(t *testing.T) {
	cfg := `
upstreams:
  backends:
    - url: "http://pdns-1:8081"
      api_key: "key-1"
    - url: "http://pdns-2:8081"
      api_key: "key-2"
  health_check:
    interval: 1s
    timeout: 2s
hmac_secrets:
  - id: "v1"
    secret: "test-secret-long-enough"
db:
  dsn: "postgres://localhost/test"
`
	cfgFile := writeConfig(t, cfg)
	_, err := Load(cfgFile)
	if err == nil {
		t.Fatal("expected error for timeout >= interval")
	}
}

func TestValidatePostgresMissingDSN(t *testing.T) {
	cfg := `
upstreams:
  backends:
    - url: "http://pdns:8081"
      api_key: "key"
hmac_secrets:
  - id: "v1"
    secret: "test-secret-long-enough"
db:
  driver: postgres
  dsn: ""
`
	cfgFile := writeConfig(t, cfg)
	_, err := Load(cfgFile)
	if err == nil {
		t.Fatal("expected error for postgres with empty DSN")
	}
}

func TestCurrentHmacSecret(t *testing.T) {
	cfg := &Config{
		HmacSecrets: []HmacSecret{
			{ID: "v2", Secret: "new"},
			{ID: "v1", Secret: "old"},
		},
	}

	s, err := cfg.CurrentHmacSecret()
	if err != nil {
		t.Fatal(err)
	}
	if s.ID != "v2" {
		t.Errorf("current secret ID = %q, want %q", s.ID, "v2")
	}
}

func TestHmacSecretByID(t *testing.T) {
	cfg := &Config{
		HmacSecrets: []HmacSecret{
			{ID: "v2", Secret: "new"},
			{ID: "v1", Secret: "old"},
		},
	}

	s, err := cfg.HmacSecretByID("v1")
	if err != nil {
		t.Fatal(err)
	}
	if s.Secret != "old" {
		t.Errorf("secret = %q, want %q", s.Secret, "old")
	}

	_, err = cfg.HmacSecretByID("v99")
	if err == nil {
		t.Fatal("expected error for unknown HMAC secret ID")
	}
}
