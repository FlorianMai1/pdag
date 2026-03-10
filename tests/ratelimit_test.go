package tests

import (
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

// TestRateLimiting starts a separate PDAG instance with rate limiting enabled
// (burst=3, rate=1/s) and verifies that exceeding the burst returns 429.
func TestRateLimiting(t *testing.T) {
	if testing.Short() {
		t.Skip("skipping rate limit e2e in short mode")
	}

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	// Reuse the already-built binary and plugins from TestMain.
	proxyPort := freePort()
	metricsPort := freePort()
	adminPort := freePort()

	// Start a second PDAG instance with rate limiting enabled.
	cfgFile, err := writeE2EConfig("pdag-e2e-ratelimit.yaml", pdagUpstreamURL)
	if err != nil {
		t.Fatalf("write ratelimit config: %v", err)
	}
	defer os.Remove(cfgFile)

	cmd := exec.CommandContext(ctx, "./pdag-test", "serve", "--config", filepath.Join("tests", cfgFile))
	cmd.Dir = ".."
	cmd.Env = append(os.Environ(),
		fmt.Sprintf("PDAG_LISTEN=:%s", proxyPort),
		fmt.Sprintf("PDAG_METRICS__LISTEN=:%s", metricsPort),
		fmt.Sprintf("PDAG_ADMIN__LISTEN=:%s", adminPort),
		"PDAG_DB__DRIVER=postgres",
		fmt.Sprintf("PDAG_DB__DSN=%s", pdagDBDSN),
		"PDAG_ADMIN_TOKEN=e2e-admin-token",
		"PDAG_AUDIT_LOG=",
	)
	cmd.Stdout = os.Stdout
	cmd.Stderr = os.Stderr

	if err := cmd.Start(); err != nil {
		t.Fatalf("start rate-limited pdag: %v", err)
	}
	defer func() {
		cancel()
		cmd.Wait()
	}()

	if err := waitForPort(proxyPort, 15*time.Second); err != nil {
		t.Fatalf("rate-limited pdag not ready: %v", err)
	}

	// Create a key via the rate-limited instance's admin API.
	keyID, secret := rlCreateKey(t, adminPort, "rl-test-user", []string{"admin"})
	apiKey := keyID + ":" + secret
	client := &http.Client{Timeout: 5 * time.Second}
	url := fmt.Sprintf("http://localhost:%s/api/v1/servers/localhost/zones", proxyPort)

	// Send burst+1 requests rapidly. First 3 should succeed, 4th should be 429.
	t.Run("burst_then_429", func(t *testing.T) {
		for i := 0; i < 4; i++ {
			req, _ := http.NewRequest("GET", url, nil)
			req.Header.Set("X-API-Key", apiKey)
			resp, err := client.Do(req)
			if err != nil {
				t.Fatalf("request %d: %v", i+1, err)
			}
			resp.Body.Close()

			if i < 3 {
				if resp.StatusCode != http.StatusOK {
					t.Errorf("request %d: status = %d, want 200", i+1, resp.StatusCode)
				}
			} else {
				if resp.StatusCode != http.StatusTooManyRequests {
					t.Errorf("request %d: status = %d, want 429", i+1, resp.StatusCode)
				}
				if ra := resp.Header.Get("Retry-After"); ra != "1" {
					t.Errorf("Retry-After = %q, want \"1\"", ra)
				}
			}
		}
	})

	// After waiting for token refill, requests should succeed again.
	t.Run("refill_allows_again", func(t *testing.T) {
		time.Sleep(1200 * time.Millisecond) // wait >1s for at least 1 token

		req, _ := http.NewRequest("GET", url, nil)
		req.Header.Set("X-API-Key", apiKey)
		resp, err := client.Do(req)
		if err != nil {
			t.Fatalf("refill request: %v", err)
		}
		resp.Body.Close()

		if resp.StatusCode != http.StatusOK {
			t.Errorf("after refill: status = %d, want 200", resp.StatusCode)
		}
	})

	// Different principal should have its own bucket.
	t.Run("per_principal_isolation", func(t *testing.T) {
		keyID2, secret2 := rlCreateKey(t, adminPort, "rl-test-user-2", []string{"admin"})
		apiKey2 := keyID2 + ":" + secret2

		req, _ := http.NewRequest("GET", url, nil)
		req.Header.Set("X-API-Key", apiKey2)
		resp, err := client.Do(req)
		if err != nil {
			t.Fatalf("isolation request: %v", err)
		}
		resp.Body.Close()

		if resp.StatusCode != http.StatusOK {
			t.Errorf("different principal: status = %d, want 200", resp.StatusCode)
		}
	})
}

// rlCreateKey creates a key via the admin API of the rate-limited PDAG instance.
func rlCreateKey(t *testing.T, adminPort, principal string, roles []string) (keyID, secret string) {
	t.Helper()
	body := fmt.Sprintf(`{"principal":%q,"roles":%s}`, principal, mustJSON(roles))
	req, _ := http.NewRequest("POST",
		fmt.Sprintf("http://localhost:%s/admin/keys", adminPort),
		strings.NewReader(body))
	req.Header.Set("Authorization", "Bearer e2e-admin-token")
	req.Header.Set("Content-Type", "application/json")

	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		t.Fatalf("create key: %v", err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusCreated {
		t.Fatalf("create key: status %d", resp.StatusCode)
	}

	var result struct {
		ID     string `json:"id"`
		Secret string `json:"secret"`
	}
	if err := json.NewDecoder(resp.Body).Decode(&result); err != nil {
		t.Fatalf("decode key response: %v", err)
	}
	return result.ID, result.Secret
}

func mustJSON(v interface{}) string {
	b, _ := json.Marshal(v)
	return string(b)
}
