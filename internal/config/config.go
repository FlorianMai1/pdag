package config

import (
	"encoding/hex"
	"errors"
	"fmt"
	"net"
	"os"
	"strings"
	"time"

	"github.com/spf13/viper"
)

type UpstreamBackend struct {
	URL        string `mapstructure:"url"`
	APIKey     string `mapstructure:"api_key"`
	APIKeyFile string `mapstructure:"api_key_file"`
}

type HealthCheckConfig struct {
	Interval time.Duration `mapstructure:"interval"`
	Timeout  time.Duration `mapstructure:"timeout"`
	Path     string        `mapstructure:"path"`
}

type Upstreams struct {
	Backends    []UpstreamBackend `mapstructure:"backends"`
	HealthCheck HealthCheckConfig `mapstructure:"health_check"`
}

type DB struct {
	Driver string `mapstructure:"driver"`
	DSN    string `mapstructure:"dsn"`
}

type Metrics struct {
	Listen string `mapstructure:"listen"`
}

type Admin struct {
	Listen string `mapstructure:"listen"`
}

type HmacSecret struct {
	ID         string `mapstructure:"id"`
	Secret     string `mapstructure:"secret"`
	SecretFile string `mapstructure:"secret_file"`
}

type CircuitBreaker struct {
	FailureThreshold int           `mapstructure:"failure_threshold"`
	SuccessThreshold int           `mapstructure:"success_threshold"`
	Cooldown         time.Duration `mapstructure:"cooldown"`
}

type PluginConfig struct {
	Path           string         `mapstructure:"path"`
	SHA256         string         `mapstructure:"sha256"`
	Timeout        time.Duration  `mapstructure:"timeout"`
	CircuitBreaker CircuitBreaker `mapstructure:"circuit_breaker"`
}

type PluginDefaults struct {
	Timeout        time.Duration  `mapstructure:"timeout"`
	CircuitBreaker CircuitBreaker `mapstructure:"circuit_breaker"`
}

type RateLimit struct {
	Enabled bool    `mapstructure:"enabled"`
	Rate    float64 `mapstructure:"rate"`  // requests per second per principal
	Burst   int     `mapstructure:"burst"` // maximum burst size per principal
}

type Tracing struct {
	Enabled    bool    `mapstructure:"enabled"`
	Endpoint   string  `mapstructure:"endpoint"`    // OTLP gRPC endpoint, e.g. "localhost:4317"
	Insecure   bool    `mapstructure:"insecure"`    // use insecure gRPC connection
	SampleRate float64 `mapstructure:"sample_rate"` // 0.0 to 1.0
}

type Config struct {
	Listen              string        `mapstructure:"listen"`
	MaxBodySize         int64         `mapstructure:"max_body_size"`
	AuditLog            string        `mapstructure:"audit_log"`
	AuditBufferSize     int           `mapstructure:"audit_buffer_size"`
	AuditLogBody        bool          `mapstructure:"audit_log_body"`
	AuditFailClosed     bool          `mapstructure:"audit_fail_closed"`
	AuditEnqueueTimeout time.Duration `mapstructure:"audit_enqueue_timeout"`
	AuditBodyMaxBytes   int           `mapstructure:"audit_body_max_bytes"`
	AuditRedactFields   []string      `mapstructure:"audit_redact_fields"`
	AdminToken          string        `mapstructure:"admin_token"`
	AdminTokenFile      string        `mapstructure:"admin_token_file"`
	ShutdownWait        time.Duration `mapstructure:"shutdown_wait"`
	KeyCleanupInterval  time.Duration `mapstructure:"key_cleanup_interval"`
	TrustedProxies      []string      `mapstructure:"trusted_proxies"`

	Upstreams   Upstreams    `mapstructure:"upstreams"`
	DB          DB           `mapstructure:"db"`
	Metrics     Metrics      `mapstructure:"metrics"`
	Admin       Admin        `mapstructure:"admin"`
	HmacSecrets []HmacSecret `mapstructure:"hmac_secrets"`
	RateLimit   RateLimit    `mapstructure:"rate_limit"`

	Tracing Tracing `mapstructure:"tracing"`

	PluginDefaults PluginDefaults          `mapstructure:"plugin_defaults"`
	Plugins        map[string]PluginConfig `mapstructure:"plugins"`
}

func Load(configPath string) (*Config, error) {
	v := viper.New()

	v.SetDefault("listen", ":8080")
	v.SetDefault("max_body_size", 1<<20) // 1 MiB
	v.SetDefault("shutdown_wait", 30*time.Second)
	v.SetDefault("metrics.listen", ":9090")
	v.SetDefault("admin.listen", ":9091")
	v.SetDefault("db.driver", "postgres")
	v.SetDefault("rate_limit.enabled", false)
	v.SetDefault("rate_limit.rate", 100.0)
	v.SetDefault("rate_limit.burst", 200)
	v.SetDefault("plugin_defaults.timeout", 500*time.Millisecond)
	v.SetDefault("plugin_defaults.circuit_breaker.failure_threshold", 5)
	v.SetDefault("plugin_defaults.circuit_breaker.success_threshold", 2)
	v.SetDefault("plugin_defaults.circuit_breaker.cooldown", 30*time.Second)

	v.SetDefault("tracing.enabled", false)
	v.SetDefault("tracing.endpoint", "localhost:4317")
	v.SetDefault("tracing.insecure", false)
	v.SetDefault("tracing.sample_rate", 1.0)

	v.SetDefault("upstreams.health_check.interval", 10*time.Second)
	v.SetDefault("upstreams.health_check.timeout", 2*time.Second)
	v.SetDefault("upstreams.health_check.path", "/api/v1/servers")

	v.SetDefault("audit_buffer_size", 4096)
	v.SetDefault("key_cleanup_interval", 0)
	v.SetDefault("audit_log_body", false)
	v.SetDefault("audit_fail_closed", false)
	v.SetDefault("audit_enqueue_timeout", 250*time.Millisecond)
	v.SetDefault("audit_body_max_bytes", 8192)
	v.SetDefault("audit_redact_fields", []string{"privatekey", "key", "secret", "tsig"})

	// Register all keys so AutomaticEnv can find them.
	v.SetDefault("audit_log", "")
	v.SetDefault("admin_token", "")
	v.SetDefault("db.dsn", "")

	v.SetEnvPrefix("PDAG")
	v.SetEnvKeyReplacer(strings.NewReplacer(".", "__"))
	v.AutomaticEnv()

	if configPath != "" {
		v.SetConfigFile(configPath)
	} else {
		v.SetConfigName("pdag")
		v.SetConfigType("yaml")
		v.AddConfigPath(".")
		v.AddConfigPath("/etc/pdag")
	}

	if err := v.ReadInConfig(); err != nil {
		var configNotFound viper.ConfigFileNotFoundError
		if !errors.As(err, &configNotFound) {
			return nil, fmt.Errorf("read config: %w", err)
		}
		// Config file not found is ok — env vars may provide everything.
	}

	var cfg Config
	if err := v.Unmarshal(&cfg); err != nil {
		return nil, fmt.Errorf("unmarshal config: %w", err)
	}

	if err := cfg.resolveSecretFiles(); err != nil {
		return nil, fmt.Errorf("resolve secret files: %w", err)
	}

	if err := cfg.validate(); err != nil {
		return nil, fmt.Errorf("validate config: %w", err)
	}

	return &cfg, nil
}

// resolveSecretFiles reads _file fields and populates the corresponding value fields.
func (c *Config) resolveSecretFiles() error {
	resolve := func(value *string, filePath, name string) error {
		if filePath != "" && *value == "" {
			data, err := os.ReadFile(filePath)
			if err != nil {
				return fmt.Errorf("%s: %w", name, err)
			}
			*value = strings.TrimSpace(string(data))
		}
		return nil
	}

	if err := resolve(&c.AdminToken, c.AdminTokenFile, "admin_token_file"); err != nil {
		return err
	}
	for i := range c.Upstreams.Backends {
		if err := resolve(&c.Upstreams.Backends[i].APIKey, c.Upstreams.Backends[i].APIKeyFile, fmt.Sprintf("upstreams.backends[%d].api_key_file", i)); err != nil {
			return err
		}
	}
	for i := range c.HmacSecrets {
		if c.HmacSecrets[i].SecretFile != "" && c.HmacSecrets[i].Secret == "" {
			data, err := os.ReadFile(c.HmacSecrets[i].SecretFile)
			if err != nil {
				return fmt.Errorf("hmac_secrets[%d].secret_file: %w", i, err)
			}
			c.HmacSecrets[i].Secret = strings.TrimSpace(string(data))
		}
	}
	return nil
}

func (c *Config) validate() error {
	// Upstream backends.
	if len(c.Upstreams.Backends) == 0 {
		return fmt.Errorf("upstreams.backends is required")
	}
	for i, b := range c.Upstreams.Backends {
		if b.URL == "" {
			return fmt.Errorf("upstreams.backends[%d].url is required", i)
		}
		if b.APIKey == "" {
			return fmt.Errorf("upstreams.backends[%d].api_key is required", i)
		}
	}

	// Listen addresses.
	for _, addr := range []struct {
		name, value string
	}{
		{"listen", c.Listen},
		{"metrics.listen", c.Metrics.Listen},
		{"admin.listen", c.Admin.Listen},
	} {
		if _, _, err := net.SplitHostPort(addr.value); err != nil {
			return fmt.Errorf("%s: invalid address %q: %w", addr.name, addr.value, err)
		}
	}

	// Port conflicts.
	addrs := map[string]string{
		c.Listen:         "listen",
		c.Metrics.Listen: "metrics.listen",
		c.Admin.Listen:   "admin.listen",
	}
	if len(addrs) < 3 {
		return fmt.Errorf("two or more servers share the same listen address: check listen, metrics.listen, and admin.listen")
	}

	// MaxBodySize.
	if c.MaxBodySize <= 0 {
		return fmt.Errorf("max_body_size must be > 0, got %d", c.MaxBodySize)
	}

	// Key cleanup interval.
	if c.KeyCleanupInterval < 0 {
		return fmt.Errorf("key_cleanup_interval must be >= 0, got %v", c.KeyCleanupInterval)
	}

	// Shutdown wait: must be positive, else graceful shutdown becomes an
	// instant hard stop (context.WithTimeout with <=0 is already expired).
	if c.ShutdownWait <= 0 {
		return fmt.Errorf("shutdown_wait must be > 0, got %v", c.ShutdownWait)
	}

	// Audit buffer size.
	if c.AuditBufferSize <= 0 {
		return fmt.Errorf("audit_buffer_size must be > 0, got %d", c.AuditBufferSize)
	}

	// Audit enqueue timeout.
	if c.AuditEnqueueTimeout < 0 {
		return fmt.Errorf("audit_enqueue_timeout must be >= 0, got %v", c.AuditEnqueueTimeout)
	}

	// Audit body cap.
	if c.AuditBodyMaxBytes < 0 {
		return fmt.Errorf("audit_body_max_bytes must be >= 0, got %d", c.AuditBodyMaxBytes)
	}

	// Trusted proxies (used for client-IP resolution / IP allowlisting).
	for i, c := range c.TrustedProxies {
		if _, _, err := net.ParseCIDR(strings.TrimSpace(c)); err != nil {
			return fmt.Errorf("trusted_proxies[%d]: invalid CIDR %q: %w", i, c, err)
		}
	}

	// Plugins.
	for name, pc := range c.Plugins {
		info, err := os.Stat(pc.Path)
		if err != nil {
			return fmt.Errorf("plugin %q: path %q: %w", name, pc.Path, err)
		}
		if info.IsDir() {
			return fmt.Errorf("plugin %q: path %q is a directory", name, pc.Path)
		}
		if info.Mode()&0111 == 0 {
			return fmt.Errorf("plugin %q: path %q is not executable", name, pc.Path)
		}
		if err := validateCircuitBreaker(pc.CircuitBreaker, fmt.Sprintf("plugins.%s", name)); err != nil {
			return err
		}
		if pc.Timeout < 0 {
			return fmt.Errorf("plugins.%s.timeout must be >= 0, got %v", name, pc.Timeout)
		}
		if pc.SHA256 != "" {
			if len(pc.SHA256) != 64 {
				return fmt.Errorf("plugins.%s.sha256 must be 64 hex characters, got %d", name, len(pc.SHA256))
			}
			if _, err := hex.DecodeString(pc.SHA256); err != nil {
				return fmt.Errorf("plugins.%s.sha256 is not valid hex: %w", name, err)
			}
		}
	}

	// Plugin defaults.
	if c.PluginDefaults.Timeout <= 0 {
		return fmt.Errorf("plugin_defaults.timeout must be > 0, got %v", c.PluginDefaults.Timeout)
	}
	if err := validateCircuitBreaker(c.PluginDefaults.CircuitBreaker, "plugin_defaults"); err != nil {
		return err
	}

	// HMAC secrets.
	if len(c.HmacSecrets) == 0 {
		return fmt.Errorf("hmac_secrets is required: at least one HMAC secret must be configured")
	}
	for i, s := range c.HmacSecrets {
		if s.ID == "" || s.Secret == "" {
			return fmt.Errorf("hmac_secrets[%d]: id and secret are required", i)
		}
		if len(s.Secret) < 16 {
			return fmt.Errorf("hmac_secrets[%d]: secret must be at least 16 bytes, got %d", i, len(s.Secret))
		}
	}

	// Rate limit.
	if c.RateLimit.Enabled {
		if c.RateLimit.Rate <= 0 {
			return fmt.Errorf("rate_limit.rate must be > 0 when enabled, got %v", c.RateLimit.Rate)
		}
		if c.RateLimit.Burst <= 0 {
			return fmt.Errorf("rate_limit.burst must be > 0 when enabled, got %d", c.RateLimit.Burst)
		}
	}

	// Health check (only relevant with multiple backends).
	if len(c.Upstreams.Backends) > 1 {
		hc := c.Upstreams.HealthCheck
		if hc.Interval <= 0 {
			return fmt.Errorf("upstreams.health_check.interval must be > 0, got %v", hc.Interval)
		}
		if hc.Timeout <= 0 {
			return fmt.Errorf("upstreams.health_check.timeout must be > 0, got %v", hc.Timeout)
		}
		if hc.Timeout >= hc.Interval {
			return fmt.Errorf("upstreams.health_check.timeout (%v) must be less than interval (%v)", hc.Timeout, hc.Interval)
		}
	}

	// Tracing.
	if c.Tracing.Enabled {
		if c.Tracing.Endpoint == "" {
			return fmt.Errorf("tracing.endpoint is required when tracing is enabled")
		}
		if c.Tracing.SampleRate < 0 || c.Tracing.SampleRate > 1 {
			return fmt.Errorf("tracing.sample_rate must be between 0.0 and 1.0, got %v", c.Tracing.SampleRate)
		}
	}

	// Database.
	if c.DB.Driver == "postgres" && c.DB.DSN == "" {
		return fmt.Errorf("db.dsn is required when db.driver is postgres")
	}

	return nil
}

func validateCircuitBreaker(cb CircuitBreaker, prefix string) error {
	// Zero values mean "use defaults", so only reject explicitly negative/invalid values.
	if cb.FailureThreshold < 0 {
		return fmt.Errorf("%s.circuit_breaker.failure_threshold must be >= 0, got %d", prefix, cb.FailureThreshold)
	}
	if cb.SuccessThreshold < 0 {
		return fmt.Errorf("%s.circuit_breaker.success_threshold must be >= 0, got %d", prefix, cb.SuccessThreshold)
	}
	if cb.Cooldown < 0 {
		return fmt.Errorf("%s.circuit_breaker.cooldown must be >= 0, got %v", prefix, cb.Cooldown)
	}
	return nil
}

// CurrentHmacSecret returns the first (active) HMAC secret, used for new key creation.
func (c *Config) CurrentHmacSecret() (HmacSecret, error) {
	if len(c.HmacSecrets) == 0 {
		return HmacSecret{}, fmt.Errorf("no hmac_secrets configured")
	}
	return c.HmacSecrets[0], nil
}

// HmacSecretByID finds an HMAC secret by its ID, used during verification.
func (c *Config) HmacSecretByID(id string) (HmacSecret, error) {
	for _, s := range c.HmacSecrets {
		if s.ID == id {
			return s, nil
		}
	}
	return HmacSecret{}, fmt.Errorf("hmac secret %q not found", id)
}

// PluginConfigResolved returns the plugin config with defaults applied for any unset fields.
func (c *Config) PluginConfigResolved(name string) (PluginConfig, error) {
	pc, ok := c.Plugins[name]
	if !ok {
		return PluginConfig{}, fmt.Errorf("plugin %q not configured", name)
	}
	if pc.Timeout == 0 {
		pc.Timeout = c.PluginDefaults.Timeout
	}
	if pc.CircuitBreaker.FailureThreshold == 0 {
		pc.CircuitBreaker.FailureThreshold = c.PluginDefaults.CircuitBreaker.FailureThreshold
	}
	if pc.CircuitBreaker.SuccessThreshold == 0 {
		pc.CircuitBreaker.SuccessThreshold = c.PluginDefaults.CircuitBreaker.SuccessThreshold
	}
	if pc.CircuitBreaker.Cooldown == 0 {
		pc.CircuitBreaker.Cooldown = c.PluginDefaults.CircuitBreaker.Cooldown
	}
	return pc, nil
}
