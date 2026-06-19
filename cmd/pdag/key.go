package main

import (
	"context"
	"flag"
	"fmt"
	"os"
	"path/filepath"
	"strings"

	adminhmac "github.com/FlorianMai1/pdag/internal/admin/hmac"
	"github.com/FlorianMai1/pdag/internal/config"
	"github.com/FlorianMai1/pdag/internal/store"
	"github.com/FlorianMai1/pdag/internal/store/postgres"
)

func runKey() error {
	if len(os.Args) < 3 {
		fmt.Fprintf(os.Stderr, "usage: pdag key <create|list|disable|enable|delete>\n")
		os.Exit(1)
	}

	subCmd := os.Args[2]
	// Shift args so flag parsing works for subcommands.
	os.Args = append(os.Args[:2], os.Args[3:]...)

	fs := flag.NewFlagSet("key", flag.ExitOnError)
	configPath := fs.String("config", "", "path to config file")

	switch subCmd {
	case "create":
		return runKeyCreate(fs, configPath)
	case "list":
		return runKeyList(fs, configPath)
	case "disable":
		return runKeySetEnabled(fs, configPath, false)
	case "enable":
		return runKeySetEnabled(fs, configPath, true)
	case "delete":
		return runKeyDelete(fs, configPath)
	default:
		return fmt.Errorf("unknown key subcommand: %s", subCmd)
	}
}

// keyEnv holds the resources needed by key subcommands.
type keyEnv struct {
	mgr    store.KeyManager
	keygen adminhmac.Generator
}

func openKeyEnv(fs *flag.FlagSet, configPath *string) (*keyEnv, func(), error) {
	_ = fs.Parse(os.Args[2:])

	cfg, err := config.Load(*configPath)
	if err != nil {
		return nil, func() {}, err
	}

	if cfg.DB.DSN == "" {
		return nil, func() {}, fmt.Errorf("key management requires a database: set db.dsn")
	}

	migrationsPath, err := filepath.Abs("migrations")
	if err != nil {
		return nil, func() {}, fmt.Errorf("resolve migrations path: %w", err)
	}

	pg, err := postgres.NewStore(cfg.DB.DSN, migrationsPath)
	if err != nil {
		return nil, func() {}, fmt.Errorf("open store: %w", err)
	}

	current, err := cfg.CurrentHmacSecret()
	if err != nil {
		pg.Close()
		return nil, func() {}, err
	}

	env := &keyEnv{
		mgr:    pg,
		keygen: adminhmac.NewGenerator(current.ID, current.Secret),
	}
	return env, func() { pg.Close() }, nil
}

func runKeyCreate(fs *flag.FlagSet, configPath *string) error {
	principal := fs.String("principal", "", "principal name (required)")
	roles := fs.String("roles", "", "comma-separated role names (required)")

	env, cleanup, err := openKeyEnv(fs, configPath)
	if err != nil {
		return err
	}
	defer cleanup()

	if *principal == "" || *roles == "" {
		return fmt.Errorf("--principal and --roles are required")
	}

	roleList := strings.Split(*roles, ",")
	for i := range roleList {
		roleList[i] = strings.TrimSpace(roleList[i])
	}

	keyID, err := env.keygen.GenerateKeyID()
	if err != nil {
		return err
	}
	secret, err := env.keygen.GenerateSecret()
	if err != nil {
		return err
	}

	rec := &store.KeyRecord{
		ID:        keyID,
		KeyHash:   env.keygen.Hash(secret),
		HmacKeyID: env.keygen.HmacKeyID(),
		Principal: *principal,
		Roles:     roleList,
		Enabled:   true,
	}

	if err := env.mgr.Create(context.Background(), rec); err != nil {
		return err
	}

	fmt.Printf("Key ID:  %s\n", keyID)
	fmt.Printf("Secret:  %s\n", secret)
	fmt.Printf("Header:  X-API-Key: %s:%s\n", keyID, secret)
	fmt.Println("\nThis secret will not be shown again.")
	return nil
}

func runKeyList(fs *flag.FlagSet, configPath *string) error {
	env, cleanup, err := openKeyEnv(fs, configPath)
	if err != nil {
		return err
	}
	defer cleanup()

	keys, err := env.mgr.List(context.Background())
	if err != nil {
		return err
	}

	if len(keys) == 0 {
		fmt.Println("No keys found.")
		return nil
	}

	fmt.Printf("%-20s %-20s %-30s %-8s %-20s\n", "ID", "PRINCIPAL", "ROLES", "ENABLED", "EXPIRES")
	for _, k := range keys {
		expires := "never"
		if k.ExpiresAt != nil {
			expires = k.ExpiresAt.Format("2006-01-02 15:04")
		}
		fmt.Printf("%-20s %-20s %-30s %-8v %-20s\n",
			k.ID, k.Principal, strings.Join(k.Roles, ","), k.Enabled, expires)
	}
	return nil
}

func runKeySetEnabled(fs *flag.FlagSet, configPath *string, enabled bool) error {
	env, cleanup, err := openKeyEnv(fs, configPath)
	if err != nil {
		return err
	}
	defer cleanup()

	args := fs.Args()
	if len(args) == 0 {
		return fmt.Errorf("key ID required")
	}
	keyID := args[0]

	if err := env.mgr.SetEnabled(context.Background(), keyID, enabled); err != nil {
		return err
	}

	action := "disabled"
	if enabled {
		action = "enabled"
	}
	fmt.Printf("Key %s %s.\n", keyID, action)
	return nil
}

func runKeyDelete(fs *flag.FlagSet, configPath *string) error {
	env, cleanup, err := openKeyEnv(fs, configPath)
	if err != nil {
		return err
	}
	defer cleanup()

	args := fs.Args()
	if len(args) == 0 {
		return fmt.Errorf("key ID required")
	}
	keyID := args[0]

	if err := env.mgr.Delete(context.Background(), keyID); err != nil {
		return err
	}

	fmt.Printf("Key %s deleted.\n", keyID)
	return nil
}
