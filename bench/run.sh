#!/usr/bin/env bash
set -euo pipefail

cd "$(dirname "$0")"
export PATH="${GOPATH:-$HOME/go}/bin:$PATH"

PDAG_URL="http://localhost:8080"
ADMIN_URL="http://localhost:9091"
ADMIN_TOKEN="bench-admin-token"
DURATION="${1:-30s}"
CONCURRENCY="${2:-50}"

# ── Preflight ─────────────────────────────────────────────────────
command -v hey >/dev/null 2>&1 || {
  echo "Installing hey..."
  go install github.com/rakyll/hey@latest
}

command -v jq >/dev/null 2>&1 || {
  echo "Error: jq is required. Install it with your package manager."
  exit 1
}

# ── Start stack ───────────────────────────────────────────────────
echo "==> Starting stack..."
docker compose up -d --build --wait

# ── Seed test zones in PowerDNS ──────────────────────────────────
PDNS_API="http://localhost:8081"
PDNS_KEY="bench-api-key"

echo "==> Seeding PowerDNS zones..."
docker compose exec pdns-1 pdnsutil create-zone bench.example.com ns1.example.com 2>/dev/null || true
docker compose exec pdns-1 pdnsutil add-record bench.example.com www A 93.184.216.34 2>/dev/null || true

# Zone with many rrsets (200 A records).
echo "==> Seeding zone with many rrsets..."
curl -sf -X POST "${PDNS_API}/api/v1/servers/localhost/zones" \
  -H "X-API-Key: ${PDNS_KEY}" -H "Content-Type: application/json" \
  -d '{"name":"bench-rrsets.example.com.","kind":"Native","nameservers":["ns1.example.com."]}' >/dev/null 2>&1 || true

RRSET_COUNT=200
BATCH_SIZE=50
for (( start=0; start<RRSET_COUNT; start+=BATCH_SIZE )); do
  end=$((start + BATCH_SIZE))
  if (( end > RRSET_COUNT )); then end=$RRSET_COUNT; fi

  rrsets=""
  for (( i=start; i<end; i++ )); do
    ip=$(printf "10.%d.%d.%d" $(( (i>>16) & 0xFF )) $(( (i>>8) & 0xFF )) $(( i & 0xFF )))
    entry=$(printf '{"name":"r%d.bench-rrsets.example.com.","type":"A","ttl":3600,"changetype":"REPLACE","records":[{"content":"%s","disabled":false}]}' "$i" "$ip")
    if [ -n "$rrsets" ]; then rrsets="${rrsets},"; fi
    rrsets="${rrsets}${entry}"
  done

  curl -sf -X PATCH "${PDNS_API}/api/v1/servers/localhost/zones/bench-rrsets.example.com." \
    -H "X-API-Key: ${PDNS_KEY}" -H "Content-Type: application/json" \
    -d "{\"rrsets\":[${rrsets}]}" >/dev/null
done
echo "    Seeded ${RRSET_COUNT} rrsets in bench-rrsets.example.com."

# Many zones (200 zones with a single A record each).
echo "==> Seeding many zones..."
ZONE_COUNT=200
for (( i=0; i<ZONE_COUNT; i++ )); do
  zone="bench-z${i}.example.com."
  curl -sf -X POST "${PDNS_API}/api/v1/servers/localhost/zones" \
    -H "X-API-Key: ${PDNS_KEY}" -H "Content-Type: application/json" \
    -d "{\"name\":\"${zone}\",\"kind\":\"Native\",\"nameservers\":[\"ns1.example.com.\"],\"rrsets\":[{\"name\":\"app.${zone}\",\"type\":\"A\",\"ttl\":3600,\"changetype\":\"REPLACE\",\"records\":[{\"content\":\"10.0.0.1\",\"disabled\":false}]}]}" >/dev/null 2>&1 || true
done
echo "    Seeded ${ZONE_COUNT} zones."

# ── Create an API key via admin API ──────────────────────────────
echo "==> Creating bench API key..."
KEY_JSON=$(curl -sf -X POST "${ADMIN_URL}/admin/keys" \
  -H "Authorization: Bearer ${ADMIN_TOKEN}" \
  -H "Content-Type: application/json" \
  -d '{"principal":"bench-runner","roles":["admin"]}')

KEY_ID=$(echo "$KEY_JSON" | jq -r .id)
KEY_SECRET=$(echo "$KEY_JSON" | jq -r .secret)
API_KEY="${KEY_ID}:${KEY_SECRET}"

echo "    Key: ${KEY_ID}"

# ── Warmup ────────────────────────────────────────────────────────
echo "==> Warmup (5s)..."
hey -z 5s -c 10 -H "X-API-Key: ${API_KEY}" "${PDAG_URL}/api/v1/servers/localhost/zones" > /dev/null 2>&1

# ── Benchmark: GET /zones ─────────────────────────────────────────
echo ""
echo "══════════════════════════════════════════════════"
echo "  GET /api/v1/servers/localhost/zones"
echo "  Duration: ${DURATION}  Concurrency: ${CONCURRENCY}"
echo "══════════════════════════════════════════════════"
hey -z "$DURATION" -c "$CONCURRENCY" \
  -H "X-API-Key: ${API_KEY}" \
  "${PDAG_URL}/api/v1/servers/localhost/zones"

# ── Benchmark: GET /zones/{zone} ─────────────────────────────────
echo ""
echo "══════════════════════════════════════════════════"
echo "  GET /api/v1/servers/localhost/zones/bench.example.com."
echo "  Duration: ${DURATION}  Concurrency: ${CONCURRENCY}"
echo "══════════════════════════════════════════════════"
hey -z "$DURATION" -c "$CONCURRENCY" \
  -H "X-API-Key: ${API_KEY}" \
  "${PDAG_URL}/api/v1/servers/localhost/zones/bench.example.com."

# ── Benchmark: GET /zones/{zone} with many rrsets ────────────────
echo ""
echo "══════════════════════════════════════════════════"
echo "  GET /zones/bench-rrsets.example.com. (${RRSET_COUNT} rrsets)"
echo "  Duration: ${DURATION}  Concurrency: ${CONCURRENCY}"
echo "══════════════════════════════════════════════════"
hey -z "$DURATION" -c "$CONCURRENCY" \
  -H "X-API-Key: ${API_KEY}" \
  "${PDAG_URL}/api/v1/servers/localhost/zones/bench-rrsets.example.com."

# ── Benchmark: GET /zones with many zones ────────────────────────
echo ""
echo "══════════════════════════════════════════════════"
echo "  GET /zones (${ZONE_COUNT}+ zones)"
echo "  Duration: ${DURATION}  Concurrency: ${CONCURRENCY}"
echo "══════════════════════════════════════════════════"
hey -z "$DURATION" -c "$CONCURRENCY" \
  -H "X-API-Key: ${API_KEY}" \
  "${PDAG_URL}/api/v1/servers/localhost/zones"

# ── Benchmark: Authz denial (valid key, plugin denies) ───────────
echo "==> Creating read_zones-only key for authz denial..."
DENY_JSON=$(curl -sf -X POST "${ADMIN_URL}/admin/keys" \
  -H "Authorization: Bearer ${ADMIN_TOKEN}" \
  -H "Content-Type: application/json" \
  -d '{"principal":"bench-denied","roles":["read_zones"]}')
DENY_ID=$(echo "$DENY_JSON" | jq -r .id)
DENY_SECRET=$(echo "$DENY_JSON" | jq -r .secret)
DENY_KEY="${DENY_ID}:${DENY_SECRET}"

echo ""
echo "══════════════════════════════════════════════════"
echo "  PATCH /zones/bench.example.com. (valid key, authz denied)"
echo "  Duration: ${DURATION}  Concurrency: ${CONCURRENCY}"
echo "══════════════════════════════════════════════════"
hey -z "$DURATION" -c "$CONCURRENCY" \
  -m PATCH \
  -H "X-API-Key: ${DENY_KEY}" \
  -H "Content-Type: application/json" \
  -d '{"rrsets":[]}' \
  "${PDAG_URL}/api/v1/servers/localhost/zones/bench.example.com."

# ── Benchmark: Authn rejection (bad key) ─────────────────────────
echo ""
echo "══════════════════════════════════════════════════"
echo "  GET /zones (invalid key — measures authn overhead)"
echo "  Duration: ${DURATION}  Concurrency: ${CONCURRENCY}"
echo "══════════════════════════════════════════════════"
hey -z "$DURATION" -c "$CONCURRENCY" \
  -H "X-API-Key: k_invalid:pdg_invalid" \
  "${PDAG_URL}/api/v1/servers/localhost/zones"

# ── Teardown ──────────────────────────────────────────────────────
echo ""
echo "==> Tearing down..."
docker compose down -v

echo "==> Done."
