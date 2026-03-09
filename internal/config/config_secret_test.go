package config

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestResolveSecretFiles(t *testing.T) {
	dir := t.TempDir()

	// Write secret files.
	apiKeyFile := filepath.Join(dir, "api_key")
	os.WriteFile(apiKeyFile, []byte("  secret-from-file\n"), 0600)

	adminFile := filepath.Join(dir, "admin_token")
	os.WriteFile(adminFile, []byte("admin-from-file"), 0600)

	hmacFile := filepath.Join(dir, "hmac_secret")
	os.WriteFile(hmacFile, []byte("hmac-from-file\n"), 0600)

	cfgFile := filepath.Join(dir, "pdag.yaml")
	os.WriteFile(cfgFile, []byte(`
upstreams:
  backends:
    - url: "http://pdns:8081"
      api_key_file: "`+apiKeyFile+`"
admin_token_file: "`+adminFile+`"
hmac_secrets:
  - id: "v1"
    secret_file: "`+hmacFile+`"
`), 0644)

	cfg, err := Load(cfgFile)
	if err != nil {
		t.Fatal(err)
	}

	if cfg.Upstreams.Backends[0].APIKey != "secret-from-file" {
		t.Errorf("backend[0].api_key = %q, want %q", cfg.Upstreams.Backends[0].APIKey, "secret-from-file")
	}
	if cfg.AdminToken != "admin-from-file" {
		t.Errorf("admin_token = %q, want %q", cfg.AdminToken, "admin-from-file")
	}
	if cfg.HmacSecrets[0].Secret != "hmac-from-file" {
		t.Errorf("hmac_secrets[0].secret = %q, want %q", cfg.HmacSecrets[0].Secret, "hmac-from-file")
	}
}

func TestResolveSecretFileInlineWins(t *testing.T) {
	dir := t.TempDir()

	// Even with a file present, inline value should not be overridden.
	apiKeyFile := filepath.Join(dir, "api_key")
	os.WriteFile(apiKeyFile, []byte("file-value"), 0600)

	cfgFile := filepath.Join(dir, "pdag.yaml")
	os.WriteFile(cfgFile, []byte(`
upstreams:
  backends:
    - url: "http://pdns:8081"
      api_key: "inline-value"
      api_key_file: "`+apiKeyFile+`"
hmac_secrets:
  - id: "v1"
    secret: "inline-hmac"
`), 0644)

	cfg, err := Load(cfgFile)
	if err != nil {
		t.Fatal(err)
	}

	if cfg.Upstreams.Backends[0].APIKey != "inline-value" {
		t.Errorf("inline value should win, got %q", cfg.Upstreams.Backends[0].APIKey)
	}
}

func TestResolveSecretFileMissing(t *testing.T) {
	dir := t.TempDir()

	cfgFile := filepath.Join(dir, "pdag.yaml")
	os.WriteFile(cfgFile, []byte(`
upstreams:
  backends:
    - url: "http://pdns:8081"
      api_key_file: "/nonexistent/file"
hmac_secrets:
  - id: "v1"
    secret: "test"
`), 0644)

	_, err := Load(cfgFile)
	if err == nil {
		t.Fatal("expected error for missing secret file")
	}
	if !strings.Contains(err.Error(), "api_key_file") {
		t.Errorf("error should mention api_key_file, got: %s", err)
	}
}

func TestValidationMissingHmacSecrets(t *testing.T) {
	dir := t.TempDir()
	cfgFile := filepath.Join(dir, "pdag.yaml")
	os.WriteFile(cfgFile, []byte(`
upstreams:
  backends:
    - url: "http://pdns:8081"
      api_key: "key"
`), 0644)

	_, err := Load(cfgFile)
	if err == nil {
		t.Fatal("expected validation error for missing hmac_secrets")
	}
	if !strings.Contains(err.Error(), "hmac_secrets") {
		t.Errorf("error should mention hmac_secrets, got: %s", err)
	}
}

func TestValidationHmacSecretEmptyID(t *testing.T) {
	dir := t.TempDir()
	cfgFile := filepath.Join(dir, "pdag.yaml")
	os.WriteFile(cfgFile, []byte(`
upstreams:
  backends:
    - url: "http://pdns:8081"
      api_key: "key"
hmac_secrets:
  - id: ""
    secret: "test"
`), 0644)

	_, err := Load(cfgFile)
	if err == nil {
		t.Fatal("expected validation error for empty hmac_secrets id")
	}
	if !strings.Contains(err.Error(), "hmac_secrets[0]") {
		t.Errorf("error should mention hmac_secrets[0], got: %s", err)
	}
}

func TestValidationPluginPath(t *testing.T) {
	dir := t.TempDir()

	cfgFile := filepath.Join(dir, "pdag.yaml")
	os.WriteFile(cfgFile, []byte(`
upstreams:
  backends:
    - url: "http://pdns:8081"
      api_key: "key"
hmac_secrets:
  - id: "v1"
    secret: "test"
plugins:
  bad_plugin:
    path: "/nonexistent/plugin"
`), 0644)

	_, err := Load(cfgFile)
	if err == nil {
		t.Fatal("expected validation error for missing plugin path")
	}
	if !strings.Contains(err.Error(), "bad_plugin") {
		t.Errorf("error should mention plugin name, got: %s", err)
	}
}

func TestValidationPluginPathIsDir(t *testing.T) {
	dir := t.TempDir()
	pluginDir := filepath.Join(dir, "plugin_dir")
	os.MkdirAll(pluginDir, 0755)

	cfgFile := filepath.Join(dir, "pdag.yaml")
	os.WriteFile(cfgFile, []byte(`
upstreams:
  backends:
    - url: "http://pdns:8081"
      api_key: "key"
hmac_secrets:
  - id: "v1"
    secret: "test"
plugins:
  bad_plugin:
    path: "`+pluginDir+`"
`), 0644)

	_, err := Load(cfgFile)
	if err == nil {
		t.Fatal("expected validation error for directory plugin path")
	}
	if !strings.Contains(err.Error(), "is a directory") {
		t.Errorf("error should mention directory, got: %s", err)
	}
}
