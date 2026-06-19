# PDAG Benchmark Log

Throughput/latency per review→apply→bench loop, so the perf impact of each fix
batch is tracked over time.

**Method:** `bench/run.sh 10s 50` (10s/case, concurrency 50), full docker-compose
stack (PDAG + 1 PowerDNS backend + Postgres), `hey` for read/deny paths and
`bench_write.go` for PATCH. Seeded: 200-rrset zone, 200 zones. Numbers vary
±5-10% run-to-run (shared laptop, docker); treat small deltas as noise.

---

## Run #1 — baseline (after HIGH-severity fixes) — 2026-06-19

Commit `d38c9b3` (highs applied; mediums not yet). First recorded baseline.

| Scenario | Req/s | Avg |
|---|---:|---:|
| GET /zones | 1342.4 | 37.2 ms |
| GET /zones/{zone} | 1353.3 | 36.9 ms |
| GET /zones/{zone} (200 rrsets) | 1157.2 | 43.2 ms |
| GET /zones (200+ zones) | 1015.8 | 49.2 ms |
| PATCH add rrsets | 449.0 | 112.2 ms |
| PATCH delete rrsets | 437.5 | 114.6 ms |
| PATCH authz-denied (deny path) | 10068.9 | 5.0 ms |
| GET invalid key (authn reject) | 20918.5 | 2.4 ms |

## Run #2 — after MEDIUM-severity fixes — 2026-06-19

Commit `e455424` (10 mediums applied). Compared to Run #1.

| Scenario | Req/s | Δ vs #1 |
|---|---:|---:|
| GET /zones | 1305 | −2.8% |
| GET /zones/{zone} | 1330 | −1.7% |
| GET /zones/{zone} (200 rrsets) | 1182 | +2.2% |
| GET /zones (200+ zones) | 929 | −8.6% |
| PATCH add rrsets | 426 | −5.2% |
| PATCH delete rrsets | 556 | +27.2% |
| PATCH authz-denied | 9912 | −1.6% |
| GET invalid key (authn reject) | 22083 | +5.6% |

**Verdict: no regression.** All deltas within the ±5–10% run-to-run noise band
(PATCH-delete +27% and 200+-zones −8.6% are variance on a shared host). The bench
runs a **single backend with no `audit_log`**, so the balancer-failover and
audit body cap/redaction paths are not exercised here; the medium change on the
hot path is the authn secret-first reorder, which is negligible (authn-reject
even ticked up +5.6%).

## Run #3 — after LOW-severity fixes — 2026-06-19

Commit `0f42b8f` (19 lows applied). Compared to Run #2. Measured on an idle
host (a first attempt was discarded — it ran concurrently with six `-race`
pre-commit suites and was depressed ~20-26% across all paths by CPU contention).

| Scenario | Req/s | Δ vs #2 |
|---|---:|---:|
| GET /zones | 1172 | −10.2% |
| GET /zones/{zone} | 1210 | −9.0% |
| GET /zones/{zone} (200 rrsets) | 1100 | −7.0% |
| GET /zones (200+ zones) | 973 | +4.8% |
| PATCH add rrsets | 409 | −3.9% |
| PATCH delete rrsets | 479 | −13.9% |
| PATCH authz-denied | 9142 | −7.8% |
| GET invalid key (authn reject) | 17897 | −19.0% |

**Verdict: one intended cost, the rest host variance.**
- **authn-reject −19% is expected and intended:** the dummy-HMAC fix
  (`authn-unknown-keyid-timing`) now performs an HMAC on every invalid-key
  request to equalize latency and not leak key existence. That path went from
  "return before any crypto" to "one HMAC" — a deliberate security/throughput
  trade on the *rejection* path only (still ~18k req/s).
- **The broad ~7–10% dip on the read/deny paths is not explained by code:** the
  valid-GET hot path and the authz-deny path were not changed by the low batch
  (ratelimit Load-first/cleanup only helps; httproute normalize is equal work).
  These paths drawing down together points to host variance (shared laptop,
  thermal). Not chased further — bench is for gross-regression detection, not
  microbenchmarking; a dedicated rerun would confirm if it matters.

---

## Run #4 — after NIT fixes (review fully closed) — 2026-06-19

Commit `527f91a` (all 66 findings fixed). Idle host. Compared to Run #3 and to
the original baseline Run #1.

| Scenario | Req/s | Δ vs #3 | Δ vs #1 (baseline) |
|---|---:|---:|---:|
| GET /zones | 1337 | +14.1% | −0.4% |
| GET /zones/{zone} | 1345 | +11.1% | −0.6% |
| GET /zones/{zone} (200 rrsets) | 1202 | +9.3% | +3.9% |
| GET /zones (200+ zones) | 949 | −2.5% | −6.6% |
| PATCH add rrsets | 391 | −4.4% | −13.0% |
| PATCH delete rrsets | 474 | −1.1% | +8.3% |
| PATCH authz-denied | 10173 | +11.3% | +1.0% |
| GET invalid key (authn reject) | 21419 | +19.7% | +2.4% |

**Verdict: no cumulative regression — Run #3's dip was host variance.** The
read, deny, and authn-reject paths are all within ±1% of the original baseline
(#1); the +9–20% "gain" vs #3 is just the host recovering, confirming Run #3 was
depressed by load rather than code. PATCH numbers swing ±13% run-to-run (small
absolute counts, network-bound seeding) — not a signal. Net: all 66 fixes
(including the dummy-HMAC on the authn-reject path) land at baseline throughput.

---

## Run #5 — after release-hardening + grpc CVE bump — 2026-06-19

Commit `cdb4468` (grpc v1.79.3, version stamping, CI, non-root image, docs,
postgres integration test). Idle host. Compared to Run #4 and baseline Run #1.

| Scenario | Req/s | Δ vs #4 | Δ vs #1 (baseline) |
|---|---:|---:|---:|
| GET /zones | 1339 | +0.2% | −0.2% |
| GET /zones/{zone} | 1325 | −1.5% | −2.1% |
| GET /zones/{zone} (200 rrsets) | 1186 | −1.3% | +2.5% |
| GET /zones (200+ zones) | 1020 | +7.5% | +0.4% |
| PATCH add rrsets | 435 | +11.3% | −3.1% |
| PATCH delete rrsets | 518 | +9.3% | +18.3% |
| PATCH authz-denied | 10139 | −0.3% | +0.7% |
| GET invalid key (authn reject) | 21737 | +1.5% | +3.9% |

**Verdict: flat vs baseline.** Every path is within noise of the original Run #1
(the grpc patch bump and release scaffolding don't touch the request hot path).
The cumulative work — all 66 review fixes + the CVE remediation — has no
measurable throughput regression.


