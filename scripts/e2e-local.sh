#!/usr/bin/env bash
#
# Automates the README "Local testing" flow end-to-end:
#   1. Generates server TLS certs (idempotent)
#   2. Builds spire-identity-exchange + the mock-github-oidc binary
#   3. For each test, restarts the mock + SIE (replay cache rejects token reuse,
#      so each test needs a fresh token / fresh JWKS pair)
#   4. Calls MintCertificate via gRPC (serverKeyGen + CSR) and the HTTP gateway
#   5. Verifies the HTTP gateway enforces TLS 1.3 (rejects TLS 1.2)
#   6. Verifies the replay cache rejects a second use of the same token
#
# Prereqs:
#   - SPIRE server running locally with its UDS at the path configured in
#     config/config.example-local.json (default: /tmp/spire-server/private/api.sock)
#   - grpcurl, openssl, curl, python3 on PATH
#
# Usage: scripts/e2e-local.sh
# Exits non-zero on any failure; cleanup runs on normal exit and on ^C / errors.

set -euo pipefail

REPO_ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
cd "$REPO_ROOT"

CONFIG="config/config.example-local.json"
GRPC_PORT=8443
HTTP_PORT=8444
MOCK_PORT=9999
SPIFFE_ID="spiffe://example.org/github/my-org/my-repo/mock-workflow-yml"

MOCK_BIN="$(mktemp -t mock-oidc.XXXXXX)"
WORKLOAD_KEY="$(mktemp -t workload-key.XXXXXX)"
WORKLOAD_CSR="$(mktemp -t workload-csr.XXXXXX)"
MOCK_LOG="$(mktemp -t sie-mock-oidc.XXXXXX.log)"
SIE_LOG="$(mktemp -t sie-server.XXXXXX.log)"

MOCK_PID=""
SIE_PID=""

# ── pretty output ─────────────────────────────────────────────────────────────
red()    { printf '\033[31m%s\033[0m\n' "$*"; }
green()  { printf '\033[32m%s\033[0m\n' "$*"; }
yellow() { printf '\033[33m%s\033[0m\n' "$*"; }
bold()   { printf '\033[1m%s\033[0m\n' "$*"; }

PASS=0
FAIL=0
pass() { green "  PASS: $*"; PASS=$((PASS+1)); }
fail() { red "  FAIL: $*"; FAIL=$((FAIL+1)); }

# ── cleanup ──────────────────────────────────────────────────────────────────
cleanup() {
  local ec=$?
  stop_services
  rm -f "$MOCK_BIN" "$WORKLOAD_KEY" "$WORKLOAD_CSR"
  if [[ $ec -ne 0 || $FAIL -ne 0 ]]; then
    yellow "Logs preserved for inspection:"
    yellow "  $MOCK_LOG"
    yellow "  $SIE_LOG"
  else
    rm -f "$MOCK_LOG" "$SIE_LOG"
  fi
  exit $ec
}
trap cleanup EXIT INT TERM

stop_services() {
  if [[ -n "$MOCK_PID" ]] && kill -0 "$MOCK_PID" 2>/dev/null; then kill "$MOCK_PID" 2>/dev/null || true; fi
  if [[ -n "$SIE_PID"  ]] && kill -0 "$SIE_PID"  2>/dev/null; then kill "$SIE_PID"  2>/dev/null || true; fi
  pkill -f "$MOCK_BIN" 2>/dev/null || true
  pkill -f "spire-identity-exchange --config $CONFIG" 2>/dev/null || true
  # Wait for ports to actually be released — SIGTERM does not release the listener instantly.
  wait_for_port_free "$GRPC_PORT" || true
  wait_for_port_free "$HTTP_PORT" || true
  wait_for_port_free "$MOCK_PORT" || true
  MOCK_PID=""
  SIE_PID=""
}

wait_for_port() {
  local port=$1 attempts=${2:-30}
  for ((i=0; i<attempts; i++)); do
    if nc -z localhost "$port" 2>/dev/null; then return 0; fi
    sleep 0.2
  done
  return 1
}

wait_for_port_free() {
  local port=$1 attempts=${2:-50}
  for ((i=0; i<attempts; i++)); do
    if ! nc -z localhost "$port" 2>/dev/null; then return 0; fi
    sleep 0.2
  done
  return 1
}

start_services() {
  stop_services
  : > "$MOCK_LOG"; : > "$SIE_LOG"

  "$MOCK_BIN" --audience spire-identity-exchange >"$MOCK_LOG" 2>&1 &
  MOCK_PID=$!
  wait_for_port "$MOCK_PORT" || { red "mock OIDC failed to bind :$MOCK_PORT"; tail -20 "$MOCK_LOG"; exit 1; }

  build/bin/spire-identity-exchange --config "$CONFIG" >"$SIE_LOG" 2>&1 &
  SIE_PID=$!
  wait_for_port "$GRPC_PORT" || { red "spire-identity-exchange failed to bind :$GRPC_PORT"; tail -20 "$SIE_LOG"; exit 1; }
  wait_for_port "$HTTP_PORT" || { red "spire-identity-exchange failed to bind :$HTTP_PORT"; tail -20 "$SIE_LOG"; exit 1; }

  # Give the JWKS sync goroutine a beat (the server binds before its first JWKS fetch completes).
  for ((i=0; i<25; i++)); do
    grep -q "JWKS cache refreshed" "$SIE_LOG" && return 0
    sleep 0.2
  done
  red "spire-identity-exchange JWKS sync did not complete in time"; tail -20 "$SIE_LOG"; exit 1
}

token_from_log() {
  grep -m1 '^export GITHUB_TOKEN=' "$MOCK_LOG" | sed 's/^export GITHUB_TOKEN="//; s/"$//'
}

# Run a gRPC MintCertificate call and return 0 if the response has a non-empty x509svid.id.path.
assert_mint_ok() {
  local label=$1 payload=$2 mode=$3   # mode = grpc | http
  local resp
  if [[ "$mode" == "grpc" ]]; then
    resp=$(grpcurl -insecure -d "$payload" "localhost:$GRPC_PORT" proto.spiffe.spireidentityexchange.SpireIdentityExchangeApi/MintCertificate 2>&1 || true)
  else
    resp=$(curl -sk -X POST "https://localhost:$HTTP_PORT/v1/mint-certificate" -H 'Content-Type: application/json' -d "$payload" || true)
  fi
  if echo "$resp" | python3 -c 'import sys,json;d=json.load(sys.stdin);assert d["x509svid"]["id"]["path"],"empty path"' 2>/dev/null; then
    pass "$label"
  else
    fail "$label"
    echo "    response: $resp" | head -3
  fi
}

# ── prereq checks ─────────────────────────────────────────────────────────────
bold "── Prereqs ──"
for cmd in grpcurl openssl curl python3 nc go; do
  command -v "$cmd" >/dev/null || { red "missing: $cmd"; exit 1; }
done
[[ -S /tmp/spire-server/private/api.sock ]] || yellow "warning: SPIRE server socket not found at /tmp/spire-server/private/api.sock — minting will fail."

# ── certs ─────────────────────────────────────────────────────────────────────
if [[ ! -f certs/server.crt || ! -f certs/server.key ]]; then
  bold "── Generating server TLS certs ──"
  mkdir -p certs
  openssl req -x509 -newkey rsa:4096 -keyout certs/server.key -out certs/server.crt \
    -sha256 -days 365 -nodes -subj "/CN=localhost" \
    -addext "subjectAltName=IP:127.0.0.1,DNS:localhost" 2>/dev/null
fi

# ── build ─────────────────────────────────────────────────────────────────────
bold "── Building binaries ──"
make build >/dev/null
go build -o "$MOCK_BIN" ./examples/mock-github-oidc

# ── workload CSR (one-time, reused across runs) ───────────────────────────────
openssl req -new -newkey rsa:2048 -nodes -keyout "$WORKLOAD_KEY" \
  -subj "/CN=workload" -addext "subjectAltName=URI:${SPIFFE_ID}" \
  -out "$WORKLOAD_CSR" 2>/dev/null
CSR_B64=$(openssl req -in "$WORKLOAD_CSR" -outform DER | base64 | tr -d '\n')

# ── Test 1: gRPC serverKeyGen ─────────────────────────────────────────────────
bold "── Test 1: gRPC serverKeyGenRequest ──"
start_services
TOK=$(token_from_log)
assert_mint_ok "x509 SVID minted (server-side keygen)" \
  "{\"githubOIDC\":{\"githubToken\":\"$TOK\"},\"serverKeyGenRequest\":{}}" grpc

# ── Test 2: gRPC mintX509SVID with CSR ────────────────────────────────────────
bold "── Test 2: gRPC mintX509SVIDRequest (CSR) ──"
start_services
TOK=$(token_from_log)
assert_mint_ok "x509 SVID minted (CSR)" \
  "{\"githubOIDC\":{\"githubToken\":\"$TOK\"},\"mintX509SVIDRequest\":{\"csr\":\"$CSR_B64\"}}" grpc

# ── Test 3: HTTP gateway ─────────────────────────────────────────────────────
bold "── Test 3: HTTP gateway POST /v1/mint-certificate ──"
start_services
TOK=$(token_from_log)
assert_mint_ok "x509 SVID minted via HTTP gateway" \
  "{\"githubOIDC\":{\"githubToken\":\"$TOK\"},\"serverKeyGenRequest\":{}}" http

# ── Test 4: TLS hardening ─────────────────────────────────────────────────────
bold "── Test 4: HTTP gateway TLS hardening ──"
# openssl exits non-zero when the server rejects the handshake; pipefail would otherwise
# poison the surrounding if-checks, so capture output without pipes first.
tls13_out=$(echo Q | openssl s_client -connect "localhost:$HTTP_PORT" -tls1_3 2>&1 || true)
proto=$(echo "$tls13_out" | awk -F': ' '/^[[:space:]]*Protocol/{gsub(/^[ \t]+/,"",$2); print $2; exit}')
[[ "$proto" == "TLSv1.3" ]] && pass "gateway negotiates TLS 1.3" || fail "expected TLSv1.3, got '$proto'"

tls12_out=$(echo Q | openssl s_client -connect "localhost:$HTTP_PORT" -tls1_2 2>&1 || true)
if echo "$tls12_out" | grep -q 'protocol version'; then
  pass "gateway rejects TLS 1.2"
else
  fail "gateway accepted TLS 1.2 (MinVersion not enforced)"
fi

# ── Test 5: replay cache ─────────────────────────────────────────────────────
bold "── Test 5: replay cache rejects token reuse ──"
start_services
TOK=$(token_from_log)
# grpcurl exits non-zero on application-level errors; capture without tripping errexit.
first=$(grpcurl -insecure -d "{\"githubOIDC\":{\"githubToken\":\"$TOK\"},\"serverKeyGenRequest\":{}}" "localhost:$GRPC_PORT" proto.spiffe.spireidentityexchange.SpireIdentityExchangeApi/MintCertificate 2>&1 || true)
if ! echo "$first" | grep -q '"x509svid"'; then
  fail "first use should have succeeded"
  echo "    $first" | head -3
else
  second=$(grpcurl -insecure -d "{\"githubOIDC\":{\"githubToken\":\"$TOK\"},\"serverKeyGenRequest\":{}}" "localhost:$GRPC_PORT" proto.spiffe.spireidentityexchange.SpireIdentityExchangeApi/MintCertificate 2>&1 || true)
  if echo "$second" | grep -q 'replay'; then
    pass "second use rejected by replay cache"
  else
    fail "second use was NOT rejected — replay cache regression"
    echo "    $second" | head -3
  fi
fi

# ── Summary ───────────────────────────────────────────────────────────────────
echo
bold "── Summary ──"
green "passed: $PASS"
if [[ $FAIL -gt 0 ]]; then
  red   "failed: $FAIL"
  exit 1
else
  green "failed: 0"
fi
