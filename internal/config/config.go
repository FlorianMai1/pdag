package config

import (
	"fmt"
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

type Config struct {
	Listen       string `mapstructure:"listen"`
	MaxBodySize  int64  `mapstructure:"max_body_size"`
	AuditLog     string `mapstructure:"audit_log"`
	AdminToken   string `mapstructure:"admin_token"`
	AdminTokenFile string `mapstructure:"admin_token_file"`
	ShutdownWait time.Duration `mapstructure:"shutdown_wait"`

	Upstreams   Upstreams    `mapstructure:"upstreams"`
	DB          DB           `mapstructure:"db"`
	Metrics     Metrics      `mapstructure:"metrics"`
	Admin       Admin        `mapstructure:"admin"`
	HmacSecrets []HmacSecret `mapstructure:"hmac_secrets"`
	RateLimit   RateLimit    `mapstructure:"rate_limit"`

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

	v.SetDefault("upstreams.health_check.interval", 10*time.Second)
	v.SetDefault("upstreams.health_check.timeout", 2*time.Second)
	v.SetDefault("upstreams.health_check.path", "/api/v1/servers")

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
		if _, ok := err.(viper.ConfigFileNotFoundError); !ok {
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
	}
	if len(c.HmacSecrets) == 0 {
		return fmt.Errorf("hmac_secrets is required: at least one HMAC secret must be configured")
	}
	for i, s := range c.HmacSecrets {
		if s.ID == "" || s.Secret == "" {
			return fmt.Errorf("hmac_secrets[%d]: id and secret are required", i)
		}
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
