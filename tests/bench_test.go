package tests

import (
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"sort"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"
)

// BenchmarkProxyGETZones measures raw proxy throughput for GET /zones.
func BenchmarkProxyGETZones(b *testing.B) {
	keyID, secret := benchCreateKey(b, "bench-user")
	url := fmt.Sprintf("http://localhost:%s/api/v1/servers/localhost/zones", pdagProxyPort)
	apiKey := keyID + ":" + secret

	client := &http.Client{Timeout: 5 * time.Second}

	b.ResetTimer()
	b.RunParallel(func(pb *testing.PB) {
		for pb.Next() {
			req, _ := http.NewRequest("GET", url, nil)
			req.Header.Set("X-API-Key", apiKey)
			resp, err := client.Do(req)
			if err != nil {
				b.Fatal(err)
			}
			resp.Body.Close()
			if resp.StatusCode != http.StatusOK {
				b.Fatalf("status = %d", resp.StatusCode)
			}
		}
	})
}

// benchCreateKey creates an admin key via raw HTTP (works with *testing.B).
func benchCreateKey(tb testing.TB, principal string) (keyID, secret string) {
	return benchCreateKeyWithRoles(tb, principal, []string{"admin"})
}

// benchCreateKeyWithRoles creates a key with specific roles via raw HTTP.
func benchCreateKeyWithRoles(tb testing.TB, principal string, roles []string) (keyID, secret string) {
	tb.Helper()
	rolesJSON, _ := json.Marshal(roles)
	body := fmt.Sprintf(`{"principal":%q,"roles":%s}`, principal, rolesJSON)
	req, _ := http.NewRequest("POST",
		fmt.Sprintf("http://localhost:%s/admin/keys", pdagAdminPort),
		strings.NewReader(body))
	req.Header.Set("Authorization", "Bearer e2e-admin-token")
	req.Header.Set("Content-Type", "application/json")

	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		tb.Fatalf("create key: %v", err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusCreated {
		tb.Fatalf("create key: status %d", resp.StatusCode)
	}

	var result struct {
		ID     string `json:"id"`
		Secret string `json:"secret"`
	}
	if err := json.NewDecoder(resp.Body).Decode(&result); err != nil {
		tb.Fatalf("decode key response: %v", err)
	}
	return result.ID, result.Secret
}

// BenchmarkProxyGETZoneManyRRsets measures proxy throughput for GET on a zone
// with a large number of resource record sets.
func BenchmarkProxyGETZoneManyRRsets(b *testing.B) {
	const rrsetCount = 200

	zone := "bench-rrsets.example.com."
	benchSeedZone(b, zone)
	benchSeedRRsets(b, zone, rrsetCount)

	keyID, secret := benchCreateKey(b, "bench-rrsets-user")
	url := fmt.Sprintf("http://localhost:%s/api/v1/servers/localhost/zones/%s", pdagProxyPort, zone)
	apiKey := keyID + ":" + secret

	client := &http.Client{Timeout: 10 * time.Second}

	b.ResetTimer()
	b.RunParallel(func(pb *testing.PB) {
		for pb.Next() {
			req, _ := http.NewRequest("GET", url, nil)
			req.Header.Set("X-API-Key", apiKey)
			resp, err := client.Do(req)
			if err != nil {
				b.Fatal(err)
			}
			io.Copy(io.Discard, resp.Body)
			resp.Body.Close()
			if resp.StatusCode != http.StatusOK {
				b.Fatalf("status = %d", resp.StatusCode)
			}
		}
	})
}

// BenchmarkProxyGETManyZones measures proxy throughput for listing zones
// when the server has a large number of zones.
func BenchmarkProxyGETManyZones(b *testing.B) {
	const zoneCount = 200

	for i := 0; i < zoneCount; i++ {
		zone := fmt.Sprintf("bench-z%d.example.com.", i)
		benchSeedZone(b, zone)
	}

	keyID, secret := benchCreateKey(b, "bench-manyzones-user")
	url := fmt.Sprintf("http://localhost:%s/api/v1/servers/localhost/zones", pdagProxyPort)
	apiKey := keyID + ":" + secret

	client := &http.Client{Timeout: 10 * time.Second}

	b.ResetTimer()
	b.RunParallel(func(pb *testing.PB) {
		for pb.Next() {
			req, _ := http.NewRequest("GET", url, nil)
			req.Header.Set("X-API-Key", apiKey)
			resp, err := client.Do(req)
			if err != nil {
				b.Fatal(err)
			}
			io.Copy(io.Discard, resp.Body)
			resp.Body.Close()
			if resp.StatusCode != http.StatusOK {
				b.Fatalf("status = %d", resp.StatusCode)
			}
		}
	})
}

// BenchmarkProxyAuthzDenied measures proxy throughput when a valid key is
// denied by the authorization plugin. Uses a read_zones key sending PATCH
// requests — the plugin receives the gRPC call and returns DENY.
// This isolates the authn + authz overhead without hitting PowerDNS.
func BenchmarkProxyAuthzDenied(b *testing.B) {
	keyID, secret := benchCreateKeyWithRoles(b, "bench-authz-denied", []string{"read_zones"})
	url := fmt.Sprintf("http://localhost:%s/api/v1/servers/localhost/zones/example.com.", pdagProxyPort)
	apiKey := keyID + ":" + secret

	client := &http.Client{Timeout: 5 * time.Second}

	b.ResetTimer()
	b.RunParallel(func(pb *testing.PB) {
		for pb.Next() {
			req, _ := http.NewRequest("PATCH", url, strings.NewReader(`{"rrsets":[]}`))
			req.Header.Set("X-API-Key", apiKey)
			req.Header.Set("Content-Type", "application/json")
			resp, err := client.Do(req)
			if err != nil {
				b.Fatal(err)
			}
			io.Copy(io.Discard, resp.Body)
			resp.Body.Close()
			if resp.StatusCode != http.StatusForbidden {
				b.Fatalf("status = %d, want 403", resp.StatusCode)
			}
		}
	})
}

// ── Benchmark seeding helpers ────────────────────────────────────────

// benchSeedZone creates a zone directly via the upstream PowerDNS API.
func benchSeedZone(tb testing.TB, zone string) {
	tb.Helper()
	body := fmt.Sprintf(`{"name":%q,"kind":"Native","nameservers":["ns1.example.com."]}`, zone)
	req, _ := http.NewRequest("POST",
		pdagUpstreamURL+"/api/v1/servers/localhost/zones",
		strings.NewReader(body))
	req.Header.Set("X-API-Key", "test-api-key")
	req.Header.Set("Content-Type", "application/json")

	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		tb.Fatalf("seed zone %s: %v", zone, err)
	}
	defer resp.Body.Close()
	// 201 = created, 409/422 = already exists (idempotent for re-runs).
	if resp.StatusCode != http.StatusCreated && resp.StatusCode != http.StatusConflict && resp.StatusCode != http.StatusUnprocessableEntity {
		respBody, _ := io.ReadAll(resp.Body)
		tb.Fatalf("seed zone %s: status %d: %s", zone, resp.StatusCode, respBody)
	}
}

// benchSeedRRsets adds n A-record rrsets to a zone via the upstream PowerDNS API.
func benchSeedRRsets(tb testing.TB, zone string, n int) {
	tb.Helper()

	// Build rrsets in batches to avoid overly large payloads.
	const batchSize = 50
	for start := 0; start < n; start += batchSize {
		end := start + batchSize
		if end > n {
			end = n
		}

		var rrsets []string
		for i := start; i < end; i++ {
			ip := fmt.Sprintf("10.%d.%d.%d", (i>>16)&0xFF, (i>>8)&0xFF, i&0xFF)
			rrsets = append(rrsets, fmt.Sprintf(
				`{"name":"r%d.%s","type":"A","ttl":3600,"changetype":"REPLACE","records":[{"content":%q,"disabled":false}]}`,
				i, zone, ip))
		}

		body := fmt.Sprintf(`{"rrsets":[%s]}`, strings.Join(rrsets, ","))
		req, _ := http.NewRequest("PATCH",
			pdagUpstreamURL+"/api/v1/servers/localhost/zones/"+zone,
			strings.NewReader(body))
		req.Header.Set("X-API-Key", "test-api-key")
		req.Header.Set("Content-Type", "application/json")

		resp, err := http.DefaultClient.Do(req)
		if err != nil {
			tb.Fatalf("seed rrsets for %s: %v", zone, err)
		}
		resp.Body.Close()
		if resp.StatusCode != http.StatusNoContent {
			tb.Fatalf("seed rrsets for %s: status %d", zone, resp.StatusCode)
		}
	}
}

// TestLoadProfile runs fixed-duration load tests and prints latency percentiles.
func TestLoadProfile(t *testing.T) {
	if testing.Short() {
		t.Skip("skipping load test in short mode")
	}

	t.Run("ListZones", func(t *testing.T) {
		keyID, secret := createTestKey(t, "load-list", []string{"admin"})
		url := fmt.Sprintf("http://localhost:%s/api/v1/servers/localhost/zones", pdagProxyPort)
		runLoadProfile(t, url, keyID+":"+secret, loadProfileOpts{
			duration: 10 * time.Second, concurrency: 50,
		})
	})

	t.Run("ZoneManyRRsets", func(t *testing.T) {
		const rrsetCount = 200
		zone := "load-rrsets.example.com."
		benchSeedZone(t, zone)
		benchSeedRRsets(t, zone, rrsetCount)

		keyID, secret := createTestKey(t, "load-rrsets", []string{"admin"})
		url := fmt.Sprintf("http://localhost:%s/api/v1/servers/localhost/zones/%s", pdagProxyPort, zone)
		runLoadProfile(t, url, keyID+":"+secret, loadProfileOpts{
			duration: 10 * time.Second, concurrency: 50,
		})
	})

	t.Run("ManyZones", func(t *testing.T) {
		const zoneCount = 200
		for i := 0; i < zoneCount; i++ {
			benchSeedZone(t, fmt.Sprintf("load-z%d.example.com.", i))
		}

		keyID, secret := createTestKey(t, "load-manyzones", []string{"admin"})
		url := fmt.Sprintf("http://localhost:%s/api/v1/servers/localhost/zones", pdagProxyPort)
		runLoadProfile(t, url, keyID+":"+secret, loadProfileOpts{
			duration: 10 * time.Second, concurrency: 50,
		})
	})

	t.Run("AuthzDenied", func(t *testing.T) {
		keyID, secret := createTestKey(t, "load-authz-denied", []string{"read_zones"})
		url := fmt.Sprintf("http://localhost:%s/api/v1/servers/localhost/zones/example.com.", pdagProxyPort)
		runLoadProfile(t, url, keyID+":"+secret, loadProfileOpts{
			duration: 10 * time.Second, concurrency: 50,
			method: "PATCH", body: `{"rrsets":[]}`, wantStatus: http.StatusForbidden,
		})
	})
}

type loadProfileOpts struct {
	duration    time.Duration
	concurrency int
	method      string // defaults to GET
	body        string // optional request body
	wantStatus  int    // defaults to 200
}

// runLoadProfile drives requests at the given URL for a fixed duration
// and reports latency percentiles.
func runLoadProfile(t *testing.T, url, apiKey string, opts loadProfileOpts) {
	t.Helper()

	method := opts.method
	if method == "" {
		method = "GET"
	}
	wantStatus := opts.wantStatus
	if wantStatus == 0 {
		wantStatus = http.StatusOK
	}

	client := &http.Client{
		Timeout: 10 * time.Second,
		Transport: &http.Transport{
			MaxIdleConnsPerHost: opts.concurrency,
		},
	}

	var (
		mu        sync.Mutex
		latencies []time.Duration
		errors    atomic.Int64
		total     atomic.Int64
	)

	deadline := time.Now().Add(opts.duration)
	var wg sync.WaitGroup

	for i := 0; i < opts.concurrency; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			var local []time.Duration
			for time.Now().Before(deadline) {
				var req *http.Request
				if opts.body != "" {
					req, _ = http.NewRequest(method, url, strings.NewReader(opts.body))
					req.Header.Set("Content-Type", "application/json")
				} else {
					req, _ = http.NewRequest(method, url, nil)
				}
				req.Header.Set("X-API-Key", apiKey)

				start := time.Now()
				resp, err := client.Do(req)
				elapsed := time.Since(start)

				total.Add(1)
				if err != nil {
					errors.Add(1)
					continue
				}
				io.Copy(io.Discard, resp.Body)
				resp.Body.Close()
				if resp.StatusCode != wantStatus {
					errors.Add(1)
					continue
				}
				local = append(local, elapsed)
			}
			mu.Lock()
			latencies = append(latencies, local...)
			mu.Unlock()
		}()
	}

	wg.Wait()

	sort.Slice(latencies, func(i, j int) bool { return latencies[i] < latencies[j] })

	n := len(latencies)
	if n == 0 {
		t.Fatal("no successful requests")
	}

	totalReqs := total.Load()
	rps := float64(totalReqs) / opts.duration.Seconds()

	t.Logf("")
	t.Logf("── Load Test Results ──────────────────────────")
	t.Logf("  Duration:    %s", opts.duration)
	t.Logf("  Concurrency: %d", opts.concurrency)
	t.Logf("  Total reqs:  %d", totalReqs)
	t.Logf("  Errors:      %d", errors.Load())
	t.Logf("  RPS:         %.0f", rps)
	t.Logf("")
	t.Logf("  Latency:")
	t.Logf("    min:  %s", latencies[0])
	t.Logf("    p50:  %s", latencies[n*50/100])
	t.Logf("    p90:  %s", latencies[n*90/100])
	t.Logf("    p95:  %s", latencies[n*95/100])
	t.Logf("    p99:  %s", latencies[n*99/100])
	t.Logf("    max:  %s", latencies[n-1])
	t.Logf("───────────────────────────────────────────────")
}
