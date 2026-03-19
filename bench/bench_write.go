// bench_write sends concurrent PATCH requests with unique rrset names to
// benchmark the write path through PDAG → PowerDNS.
//
// Usage:
//
//	go run bench_write.go -url URL -key KEY -zone ZONE -op add|delete -duration 30s -concurrency 10
package main

import (
	"flag"
	"fmt"
	"context"
	"io"
	"net/http"
	"os"
	"sort"
	"strings"
	"sync"
	"sync/atomic"
	"time"
)

func main() {
	var (
		url         = flag.String("url", "", "PDAG zone URL to PATCH")
		apiKey      = flag.String("key", "", "X-API-Key value (keyID:secret)")
		zone        = flag.String("zone", "", "zone FQDN (e.g. bench-write.example.com.)")
		op          = flag.String("op", "add", "operation: add or delete")
		duration    = flag.Duration("duration", 30*time.Second, "benchmark duration")
		concurrency = flag.Int("concurrency", 10, "number of concurrent workers")
	)
	flag.Parse()

	if *url == "" || *apiKey == "" || *zone == "" {
		fmt.Fprintln(os.Stderr, "url, key, and zone are required")
		os.Exit(1)
	}

	client := &http.Client{Timeout: 10 * time.Second}
	deadline := time.Now().Add(*duration)

	var (
		counter   atomic.Int64
		total     atomic.Int64
		errors    atomic.Int64
		statuses  sync.Map
		mu        sync.Mutex
		latencies []time.Duration
	)

	var wg sync.WaitGroup
	for range *concurrency {
		wg.Add(1)
		go func() {
			defer wg.Done()
			for time.Now().Before(deadline) {
				n := counter.Add(1)
				name := fmt.Sprintf("bw%d.%s", n, *zone)

				var body string
				switch *op {
				case "add":
					ip := fmt.Sprintf("10.%d.%d.%d", (n>>16)&0xFF, (n>>8)&0xFF, n&0xFF)
					body = fmt.Sprintf(
						`{"rrsets":[{"name":"%s","type":"A","ttl":3600,"changetype":"REPLACE","records":[{"content":"%s","disabled":false}]}]}`,
						name, ip,
					)
				case "delete":
					body = fmt.Sprintf(
						`{"rrsets":[{"name":"%s","type":"A","changetype":"DELETE"}]}`,
						name,
					)
				default:
					fmt.Fprintf(os.Stderr, "unknown op: %s\n", *op)
					os.Exit(1)
				}

				req, err := http.NewRequestWithContext(context.Background(), "PATCH", *url, strings.NewReader(body))
				if err != nil {
					errors.Add(1)
					continue
				}
				req.Header.Set("X-API-Key", *apiKey)
				req.Header.Set("Content-Type", "application/json")

				start := time.Now()
				resp, err := client.Do(req)
				elapsed := time.Since(start)

				if err != nil {
					errors.Add(1)
					continue
				}
				_, _ = io.Copy(io.Discard, resp.Body)
				resp.Body.Close()

				total.Add(1)
				mu.Lock()
				latencies = append(latencies, elapsed)
				mu.Unlock()

				key := fmt.Sprintf("%d", resp.StatusCode)
				if v, ok := statuses.Load(key); ok {
					statuses.Store(key, v.(int64)+1)
				} else {
					statuses.Store(key, int64(1))
				}
			}
		}()
	}
	wg.Wait()

	// Compute stats.
	mu.Lock()
	sort.Slice(latencies, func(i, j int) bool { return latencies[i] < latencies[j] })
	n := len(latencies)
	mu.Unlock()

	if n == 0 {
		fmt.Println("No requests completed.")
		return
	}

	var sum time.Duration
	for _, l := range latencies {
		sum += l
	}

	pct := func(p float64) time.Duration {
		idx := int(float64(n) * p)
		if idx >= n {
			idx = n - 1
		}
		return latencies[idx]
	}

	elapsed := *duration
	rps := float64(total.Load()) / elapsed.Seconds()

	fmt.Printf("\nSummary:\n")
	fmt.Printf("  Total:        %.4f secs\n", elapsed.Seconds())
	fmt.Printf("  Requests:     %d\n", total.Load())
	fmt.Printf("  Errors:       %d\n", errors.Load())
	fmt.Printf("  Requests/sec: %.2f\n", rps)
	fmt.Printf("  Fastest:      %.4f secs\n", latencies[0].Seconds())
	fmt.Printf("  Slowest:      %.4f secs\n", latencies[n-1].Seconds())
	fmt.Printf("  Average:      %.4f secs\n", (sum / time.Duration(n)).Seconds())
	fmt.Println()
	fmt.Println("Latency distribution:")
	for _, p := range []float64{0.50, 0.75, 0.90, 0.95, 0.99} {
		fmt.Printf("  %.0f%% in %.4f secs\n", p*100, pct(p).Seconds())
	}
	fmt.Println()
	fmt.Println("Status code distribution:")
	statuses.Range(func(k, v any) bool {
		fmt.Printf("  [%s] %d responses\n", k.(string), v.(int64))
		return true
	})
	fmt.Println()
}
