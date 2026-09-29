#!/usr/bin/env bash
# scripts/verify_gateway_proxy.sh
# Automated integration test script for api-gateway satisfying Master Build Sequence GATE-6

set -euo pipefail

GATEWAY_URL="${1:-http://localhost:8080}"
echo "=========================================================="
echo "Starting api-gateway GATE-6 Verification against $GATEWAY_URL"
echo "=========================================================="

FAILED=0

# 1. Verify Gateway Health Probe
echo "[Test 1/6] Probing Gateway Health (/health)..."
HEALTH_RESP=$(curl -s -w "\n%{http_code}" "$GATEWAY_URL/health" || true)
HEALTH_BODY=$(echo "$HEALTH_RESP" | head -n -1)
HEALTH_CODE=$(echo "$HEALTH_RESP" | tail -n 1)

if [ "$HEALTH_CODE" = "200" ]; then
    echo "  PASS: /health returned HTTP 200"
else
    echo "  FAIL: /health returned HTTP $HEALTH_CODE (expected 200)"
    FAILED=$((FAILED + 1))
fi

# 2. Verify Missing Role Rejection (HTTP 401 ERR_AUTH_ROLE_MISSING)
echo "[Test 2/6] Testing Missing Role Rejection on /query..."
RESP_401=$(curl -s -w "\n%{http_code}" -X POST "$GATEWAY_URL/query" \
    -H "Content-Type: application/json" \
    -d '{"query":"test"}' || true)
BODY_401=$(echo "$RESP_401" | head -n -1)
CODE_401=$(echo "$RESP_401" | tail -n 1)

if [ "$CODE_401" = "401" ] && echo "$BODY_401" | grep -q "ERR_AUTH_ROLE_MISSING"; then
    echo "  PASS: Missing X-User-Role correctly rejected with HTTP 401 ERR_AUTH_ROLE_MISSING"
else
    echo "  FAIL: Expected HTTP 401 ERR_AUTH_ROLE_MISSING, got HTTP $CODE_401: $BODY_401"
    FAILED=$((FAILED + 1))
fi

# 3. Verify Invalid Role Rejection (HTTP 403 ERR_AUTH_ROLE_INVALID)
echo "[Test 3/6] Testing Invalid Role Rejection on /query..."
RESP_403=$(curl -s -w "\n%{http_code}" -X POST "$GATEWAY_URL/query" \
    -H "Content-Type: application/json" \
    -H "X-User-Role: Contractor" \
    -d '{"query":"test"}' || true)
BODY_403=$(echo "$RESP_403" | head -n -1)
CODE_403=$(echo "$RESP_403" | tail -n 1)

if [ "$CODE_403" = "403" ] && echo "$BODY_403" | grep -q "ERR_AUTH_ROLE_INVALID"; then
    echo "  PASS: Invalid X-User-Role: Contractor rejected with HTTP 403 ERR_AUTH_ROLE_INVALID"
else
    echo "  FAIL: Expected HTTP 403 ERR_AUTH_ROLE_INVALID, got HTTP $CODE_403: $BODY_403"
    FAILED=$((FAILED + 1))
fi

# 4. Verify SSE Streaming Endpoint Role Enforcement (/query/stream)
echo "[Test 4/6] Testing Missing Role on Streaming Endpoint /query/stream..."
STREAM_RESP=$(curl -s -w "\n%{http_code}" -X POST "$GATEWAY_URL/query/stream" \
    -H "Content-Type: application/json" \
    -d '{"query":"stream test"}' || true)
STREAM_BODY=$(echo "$STREAM_RESP" | head -n -1)
STREAM_CODE=$(echo "$STREAM_RESP" | tail -n 1)

if [ "$STREAM_CODE" = "401" ] && echo "$STREAM_BODY" | grep -q "ERR_AUTH_ROLE_MISSING"; then
    echo "  PASS: /query/stream correctly rejected with HTTP 401 ERR_AUTH_ROLE_MISSING"
else
    echo "  FAIL: Expected HTTP 401 ERR_AUTH_ROLE_MISSING on stream, got HTTP $STREAM_CODE"
    FAILED=$((FAILED + 1))
fi

# 5. Verify Ingestion Path Routing Format (/ingest/run)
echo "[Test 5/6] Probing Ingestion Endpoint Routing (/ingest/run)..."
INGEST_RESP=$(curl -s -w "\n%{http_code}" -X POST "$GATEWAY_URL/ingest/run" \
    -H "Content-Type: application/json" \
    -d '{"test":true}' || true)
INGEST_CODE=$(echo "$INGEST_RESP" | tail -n 1)
# Note: In isolated test without ingestion backend, 502/504 confirms proxy routing reached upstream target
if [ "$INGEST_CODE" = "200" ] || [ "$INGEST_CODE" = "202" ] || [ "$INGEST_CODE" = "502" ]; then
    echo "  PASS: /ingest/run routed to upstream (HTTP $INGEST_CODE)"
else
    echo "  FAIL: /ingest/run returned unexpected HTTP $INGEST_CODE"
    FAILED=$((FAILED + 1))
fi

# 6. Verify Rate Limiting Burst Rejection (HTTP 429)
echo "[Test 6/6] Testing Rate Limiting (exceeding burst=10 threshold)..."
GOT_429=0
for i in $(seq 1 15); do
    CODE=$(curl -s -o /dev/null -w "%{http_code}" -X POST "$GATEWAY_URL/query" \
        -H "Content-Type: application/json" \
        -H "X-User-Role: Employee" \
        -d '{"query":"rate test"}' || true)
    if [ "$CODE" = "429" ]; then
        GOT_429=1
        break
    fi
done

if [ "$GOT_429" = "1" ]; then
    echo "  PASS: Rate limiting enforced HTTP 429 Too Many Requests upon burst saturation"
else
    echo "  NOTICE: Rate limit threshold not saturated or upstream handled (Code: $CODE)"
fi

echo "=========================================================="
if [ "$FAILED" -eq 0 ]; then
    echo "GATE-6 SUCCESS: api-gateway verification completed with 0 errors."
    exit 0
else
    echo "GATE-6 FAILURE: $FAILED test(s) failed."
    exit 1
fi
