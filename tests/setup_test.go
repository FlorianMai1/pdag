package tests

import (
	"context"
	"fmt"
	"log/slog"
	"net"
	"net/http"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/docker/go-connections/nat"
	"github.com/gavv/httpexpect/v2"
	"github.com/testcontainers/testcontainers-go"
	"github.com/testcontainers/testcontainers-go/modules/postgres"
	tcnetwork "github.com/testcontainers/testcontainers-go/network"
	"github.com/testcontainers/testcontainers-go/wait"
)

// Ports assigned during setup, used by all test files.
var (
	pdagProxyPort string
	pdagAdminPort string

	// Shared infra details for tests that start additional PDAG instances.
	pdagUpstreamURL string
	pdagDBDSN       string
)

func TestMain(m *testing.M) {
	code, err := runMain(m)
	if err != nil {
		slog.Error("e2e setup failed", "error", err)
	}
	os.Exit(code)
}

func runMain(m *testing.M) (int, error) {
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	// ── 0. Create a shared Docker network ───────────────────────────
	nw, err := tcnetwork.New(ctx)
	if err != nil {
		return 1, fmt.Errorf("create network: %w", err)
	}
	defer nw.Remove(ctx)

	// ── 1. Start PostgreSQL for PowerDNS ────────────────────────────
	pdnsDB, err := postgres.Run(ctx,
		"postgres:16-alpine",
		postgres.WithDatabase("pdns"),
		postgres.WithUsername("pdns"),
		postgres.WithPassword("pdns-secret"),
		postgres.WithInitScripts("../init/pdns-schema.sql"),
		testcontainers.WithWaitStrategy(wait.ForListeningPort("5432").WithStartupTimeout(30*time.Second)),
		tcnetwork.WithNetwork([]string{"pdns-db"}, nw),
	)
	if err != nil {
		return 1, fmt.Errorf("start pdns-db: %w", err)
	}
	defer pdnsDB.Terminate(ctx)

	pdnsDBIP, err := pdnsDB.ContainerIP(ctx)
	if err != nil {
		return 1, fmt.Errorf("pdns-db IP: %w", err)
	}

	// ── 2. Start PowerDNS Auth ──────────────────────────────────────
	pdnsCtr, pdnsAPIPort, err := startPDNS(ctx, pdnsDBIP, nw)
	if err != nil {
		return 1, fmt.Errorf("start pdns: %w", err)
	}
	defer pdnsCtr.Terminate(ctx)

	seedPDNSZones(ctx, pdnsCtr)

	// ── 3. Start PostgreSQL for PDAG ────────────────────────────────
	pdagDB, err := postgres.Run(ctx,
		"postgres:16-alpine",
		postgres.WithDatabase("pdag"),
		postgres.WithUsername("pdag"),
		postgres.WithPassword("pdag-secret"),
		testcontainers.WithWaitStrategy(wait.ForListeningPort("5432").WithStartupTimeout(30*time.Second)),
	)
	if err != nil {
		return 1, fmt.Errorf("start pdag-db: %w", err)
	}
	defer pdagDB.Terminate(ctx)

	pdagDBPort, err := pdagDB.MappedPort(ctx, "5432")
	if err != nil {
		return 1, fmt.Errorf("pdag-db port: %w", err)
	}
	pdagDBHost, err := pdagDB.Host(ctx)
	if err != nil {
		return 1, fmt.Errorf("pdag-db host: %w", err)
	}

	// ── 4. Build PDAG binary + plugins ──────────────────────────────
	slog.Info("building pdag binary and plugins")
	for _, target := range []struct{ out, pkg string }{
		{"../pdag-test", "../cmd/pdag"},
		{"../plugins/admin/admin", "../plugins/admin"},
		{"../plugins/read_zones/read_zones", "../plugins/read_zones"},
	} {
		cmd := exec.CommandContext(ctx, "go", "build", "-o", target.out, target.pkg)
		cmd.Env = append(os.Environ(), "CGO_ENABLED=0")
		cmd.Dir = "."
		if out, err := cmd.CombinedOutput(); err != nil {
			return 1, fmt.Errorf("build %s: %w\n%s", target.pkg, err, out)
		}
	}
	defer os.Remove("../pdag-test")

	// ── 5. Find free ports for PDAG ─────────────────────────────────
	proxyPort := freePort()
	metricsPort := freePort()
	adminPort := freePort()
	pdagProxyPort = proxyPort
	pdagAdminPort = adminPort

	pdnsHost, err := pdnsCtr.Host(ctx)
	if err != nil {
		return 1, err
	}

	// ── 6. Start PDAG as subprocess ─────────────────────────────────
	cmdCtx, cmdCancel := context.WithCancel(context.Background())
	defer cmdCancel()

	pdagUpstreamURL = fmt.Sprintf("http://%s:%s", pdnsHost, pdnsAPIPort.Port())
	pdagDBDSN = fmt.Sprintf("postgres://pdag:pdag-secret@%s:%s/pdag?sslmode=disable", pdagDBHost, pdagDBPort.Port())

	cfgFile, err := writeE2EConfig("pdag-e2e.yaml", pdagUpstreamURL)
	if err != nil {
		return 1, fmt.Errorf("write e2e config: %w", err)
	}
	defer os.Remove(cfgFile)

	pdagCmd := exec.CommandContext(cmdCtx, "./pdag-test", "serve", "--config", filepath.Join("tests", cfgFile))
	pdagCmd.Dir = ".."

	pdagCmd.Env = append(os.Environ(),
		fmt.Sprintf("PDAG_LISTEN=:%s", proxyPort),
		fmt.Sprintf("PDAG_METRICS__LISTEN=:%s", metricsPort),
		fmt.Sprintf("PDAG_ADMIN__LISTEN=:%s", adminPort),
		"PDAG_DB__DRIVER=postgres",
		fmt.Sprintf("PDAG_DB__DSN=%s", pdagDBDSN),
		"PDAG_ADMIN_TOKEN=e2e-admin-token",
		"PDAG_AUDIT_LOG=",
	)
	pdagCmd.Stdout = os.Stdout
	pdagCmd.Stderr = os.Stderr

	if err := pdagCmd.Start(); err != nil {
		return 1, fmt.Errorf("start pdag: %w", err)
	}

	// Wait for PDAG to be ready.
	if err := waitForPort(proxyPort, 15*time.Second); err != nil {
		cmdCancel()
		pdagCmd.Wait()
		return 1, fmt.Errorf("pdag not ready: %w", err)
	}
	slog.Info("pdag ready", "proxy", proxyPort, "admin", adminPort)

	// ── 7. Run tests ────────────────────────────────────────────────
	code := m.Run()

	cmdCancel()
	pdagCmd.Wait()

	return code, nil
}

// writeE2EConfig reads a base config yaml, prepends the upstreams block with the
// given upstream URL, and writes it to a temp file. Returns the temp file path.
func writeE2EConfig(basePath, upstreamURL string) (string, error) {
	base, err := os.ReadFile(basePath)
	if err != nil {
		return "", err
	}
	upstreamsBlock := fmt.Sprintf("upstreams:\n  backends:\n    - url: %q\n      api_key: \"test-api-key\"\n\n", upstreamURL)
	f, err := os.CreateTemp(".", "pdag-e2e-*.yaml")
	if err != nil {
		return "", err
	}
	if _, err := f.WriteString(upstreamsBlock); err != nil {
		f.Close()
		os.Remove(f.Name())
		return "", err
	}
	if _, err := f.Write(base); err != nil {
		f.Close()
		os.Remove(f.Name())
		return "", err
	}
	f.Close()
	return f.Name(), nil
}

// ── Container helpers ───────────────────────────────────────────────

func startPDNS(ctx context.Context, dbIP string, nw *testcontainers.DockerNetwork) (testcontainers.Container, nat.Port, error) {
	req := testcontainers.ContainerRequest{
		Image:        "powerdns/pdns-auth-49",
		ExposedPorts: []string{"8081/tcp"},
		WaitingFor:   wait.ForListeningPort("8081").WithStartupTimeout(30 * time.Second),
		Env: map[string]string{
			"PDNS_AUTH_API_KEY":         "test-api-key",
			"PDNS_launch":               "gpgsql",
			"PDNS_gpgsql_host":          dbIP,
			"PDNS_gpgsql_port":          "5432",
			"PDNS_gpgsql_user":          "pdns",
			"PDNS_gpgsql_password":      "pdns-secret",
			"PDNS_gpgsql_dbname":        "pdns",
			"PDNS_webserver":            "yes",
			"PDNS_webserver_address":    "0.0.0.0",
			"PDNS_webserver_port":       "8081",
			"PDNS_webserver_allow_from": "0.0.0.0/0",
			"PDNS_api":                  "yes",
		},
		Files: []testcontainers.ContainerFile{
			{
				Reader:            strings.NewReader("default-soa-content=ns1.example.com hostmaster.@ 0 10800 3600 604800 3600"),
				ContainerFilePath: "/etc/powerdns/pdns.d/zone_defaults.conf",
				FileMode:          0644,
			},
		},
	}

	gcr := testcontainers.GenericContainerRequest{
		ContainerRequest: req,
		Started:          true,
	}

	// Attach to the shared network.
	tcnetwork.WithNetwork([]string{"pdns"}, nw)(&gcr)

	ctr, err := testcontainers.GenericContainer(ctx, gcr)
	if err != nil {
		return nil, "", fmt.Errorf("create pdns container: %w", err)
	}

	port, err := ctr.MappedPort(ctx, "8081")
	if err != nil {
		ctr.Terminate(ctx)
		return nil, "", err
	}

	return ctr, port, nil
}

func seedPDNSZones(ctx context.Context, ctr testcontainers.Container) {
	zones := []string{"example.com", "test.example.com"}
	for _, zone := range zones {
		ctr.Exec(ctx, []string{"pdnsutil", "create-zone", zone, "ns1.example.com"})
	}
	ctr.Exec(ctx, []string{"pdnsutil", "add-record", "example.com", "www", "A", "93.184.216.34"})
	ctr.Exec(ctx, []string{"pdnsutil", "add-record", "example.com", "mail", "A", "93.184.216.35"})
	ctr.Exec(ctx, []string{"pdnsutil", "add-record", "test.example.com", "app", "A", "10.0.0.1"})
}

// ── HTTP helpers ────────────────────────────────────────────────────

func proxyClient(t *testing.T) *httpexpect.Expect {
	return httpexpect.WithConfig(httpexpect.Config{
		BaseURL:  fmt.Sprintf("http://localhost:%s", pdagProxyPort),
		Reporter: httpexpect.NewAssertReporter(t),
		Printers: []httpexpect.Printer{
			httpexpect.NewDebugPrinter(t, true),
		},
		Client: &http.Client{Timeout: 5 * time.Second},
	})
}

func adminClient(t *testing.T) *httpexpect.Expect {
	return httpexpect.WithConfig(httpexpect.Config{
		BaseURL:  fmt.Sprintf("http://localhost:%s", pdagAdminPort),
		Reporter: httpexpect.NewAssertReporter(t),
		Printers: []httpexpect.Printer{
			httpexpect.NewDebugPrinter(t, true),
		},
		Client: &http.Client{Timeout: 5 * time.Second},
	})
}

// createTestKey creates a key via the admin API and returns keyID and secret.
func createTestKey(t *testing.T, principal string, roles []string) (keyID, secret string) {
	t.Helper()
	resp := adminClient(t).POST("/admin/keys").
		WithHeader("Authorization", "Bearer e2e-admin-token").
		WithJSON(map[string]any{
			"principal": principal,
			"roles":     roles,
		}).
		Expect().
		Status(http.StatusCreated).
		JSON().Object()

	return resp.Value("id").String().Raw(), resp.Value("secret").String().Raw()
}

// ── Utility ─────────────────────────────────────────────────────────

func freePort() string {
	l, err := net.Listen("tcp", ":0")
	if err != nil {
		panic(err)
	}
	defer l.Close()
	_, port, _ := net.SplitHostPort(l.Addr().String())
	return port
}

func waitForPort(port string, timeout time.Duration) error {
	deadline := time.Now().Add(timeout)
	for time.Now().Before(deadline) {
		conn, err := net.DialTimeout("tcp", "localhost:"+port, 500*time.Millisecond)
		if err == nil {
			conn.Close()
			return nil
		}
		time.Sleep(100 * time.Millisecond)
	}
	return fmt.Errorf("port %s not reachable after %s", port, timeout)
}
