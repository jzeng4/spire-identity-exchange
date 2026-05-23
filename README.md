# spire-identity-exchange

An agentless SPIRE integration service that bridges workload identity attestation to the [SPIRE](https://spiffe.io/docs/latest/spire-about/) server — without requiring a SPIRE agent on every workload host.

[![Apache 2.0 License](https://img.shields.io/github/license/spiffe/spire-identity-exchange)](https://opensource.org/licenses/Apache-2.0)
[![Development Phase](https://github.com/spiffe/spiffe/blob/main/.img/maturity/dev.svg)](https://github.com/spiffe/spiffe/blob/main/MATURITY.md#development)

## Warning

This code is in an early and experimental stage of development. Please do not use it in production yet. Please consider testing it out, providing feedback,
and possibly submitting fixes.

## Background
The traditional SPIRE agent model works well in many environments, but we encountered scenarios where it is not the best fit:

- The overhead of dynamically registering short-lived workloads
- Environments where deploying a SPIRE agent is not possible
- The operational burden of managing agents across multiple platforms

To address these gaps, we introduced an agentless approach: spire-identity-exchange is an intermediate gRPC service that performs workload attestation and authentication, then calls the SPIRE server API directly to mint X.509 SVIDs. Workloads authenticate using tokens they already possess (GitHub Actions OIDC tokens, Kubernetes service account tokens) without needing a local agent.

Upstreaming this as an open-source project provides a sustainable, community-supported solution rather than an isolated internal fix — reducing fragmentation and helping other organizations avoid duplicating the same work.

More details can be found in our talk at **KubeCon + SecurityCon 2025**:
[From Adoption to Innovation: LinkedIn's SPIRE Journey](https://static.sched.com/hosted_files/colocatedeventsna2025/eb/From%20Adoption%20to%20Innovation%20LinkedIn%E2%80%99s%20SPIRE%20Journey.pdf)

## Architecture

```
  ┌──────────────────────── Identity Providers (pluggable) ─────────────────────────┐
  │  GitHub Actions  │  Kubernetes SA  │  GCP / AWS / Azure  │  Any OIDC-compatible │
  │  (OIDC / JWKS)   │  (TokenReview)  │  (IMDS / JWKS)      │  custom plugin       │
  └─────────────────────────────────────────────────┬───────────────────────────────┘
                                                    │ token validation
                                                    │
                                                    ▼
                               ┌──────────────────────────────────────────┐
                               │          spire-identity-exchange         │
                               │                                          │
                               │   config file ≈ registration entries     │
                               │                                          │
                               │   1. check replay cache (if applicable)  │
                               │   2. validate token                      │
                               │   3. evaluate CEL policy                 │
┌──────────┐  [A] token + CSR  │   4. match config registration entry     │
│          │  [B] token only   │   5. verify CSR [A] / generate key [B]   │
│ Workload │ ─── gRPC (TLS) ─► │                                          │
│          │ ◄──────────────── │                                          │
└──────────┘  X.509 SVID       │                                          │
              or JWT SVID      │                                          │
                               └─────────────────────┬────────────────────┘
                                                ▲    │
                                  X.509 SVID /  │    │  Unix socket
                                  JWT SVID      │    │  or Workload API (TLS)
                                                │    ▼
                                           SPIRE Server
```

For multi-instance deployments, the replay cache should be backed by a shared central store (e.g. Redis) so that a token cannot be replayed against a different instance.

## Deployment Modes

spire-identity-exchange supports two deployment topologies that differ in how spire-identity-exchange itself authenticates to the SPIRE server.

### Mode 1: Co-located with SPIRE Server

spire-identity-exchange runs on the same host as the SPIRE server and connects to it directly via a Unix domain socket. No attestation of spire-identity-exchange itself is required — Unix socket access is implicitly trusted by the SPIRE server.


This is the simpler deployment model and is appropriate for small or single-node setups. The trade-off is that a compromised spire-identity-exchange process has direct local access to the SPIRE server socket — see the threat model for mitigations.

### Mode 2: Separate Host with Workload Attestation

> **Status:** Under design and development — not yet implemented.

spire-identity-exchange runs on a dedicated host, separate from the SPIRE server. In this mode, spire-identity-exchange must authenticate itself to the SPIRE server before it can call `MintX509SVID`. It does this by attesting itself through the standard SPIRE workload attestation flow:

1. A SPIRE agent runs on the same host as spire-identity-exchange
2. The SPIRE agent attests the spire-identity-exchange process as a workload and issues it its own X.509 SVID
3. spire-identity-exchange presents that SVID over mTLS when connecting to the SPIRE server API


This topology provides stronger isolation — a compromised spire-identity-exchange process cannot directly access the SPIRE server socket. The SPIRE agent handles attestation of spire-identity-exchange using any SPIRE-supported workload attestor (Unix, Kubernetes, Docker, etc.), and the resulting SVID scopes spire-identity-exchange's privilege on the SPIRE server to only what it needs.

Workloads call spire-identity-exchange's `MintCertificate` RPC with:
1. An authentication token (GitHub OIDC or Kubernetes SA)
2. A CSR containing the expected SPIFFE ID as a URI SAN

spire-identity-exchange validates the token, derives the SPIFFE ID from the token claims using a configurable Go template, verifies the CSR matches, and calls the SPIRE server's `MintX509SVID` API to issue the certificate.

## Supported Authentication Methods

| Method | Description |
|---|---|
| **GitHub Actions OIDC** | Validates GitHub Actions OIDC JWTs via JWKS. Supports allowlisting by repository and required claims. |
| **Kubernetes Service Account** | Validates K8s SA tokens via the Kubernetes TokenReview API using mTLS. |

## Prerequisites

- spire-identity-exchange must run on the **same host as the SPIRE server**, as it communicates with it via a Unix domain socket
- A running [SPIRE server](https://spiffe.io/docs/latest/deploying/install-server/)
- Go 1.24+

## Building

```bash
make build
# binary at build/bin/spire-identity-exchange
```

## Configuration

spire-identity-exchange is configured via a JSON file passed with `--config`.

```bash
build/bin/spire-identity-exchange --config config.example.json
```

### Full configuration reference

```jsonc
{
  "enabled": true,
  "name": "spire-identity-exchange",
  "logLevel": "info",

  "server": {
    "port": 8443,           // gRPC server port
    "metricsPort": 9090,    // Prometheus metrics port
    "tls": {
      "certFile": "certs/server.crt",
      "keyFile":  "certs/server.key"
    }
  },

  "spire": {
    "unixSocketPath": "/tmp/spire-server/private/api.sock",
    "trustDomain": "example.org",
    "svidTTL": "1h"         // Duration string (e.g. "1h", "30m") or nanoseconds
  },

  // GitHub Actions OIDC validator
  "githubOIDC": {
    "enabled": true,
    "issuer": "https://token.actions.githubusercontent.com",
    "audiences": ["spire-identity-exchange"],
    "jwksUri": "",           // Optional — defaults to GitHub's well-known JWKS endpoint
    "spiffeIdTemplate": "spiffe://example.org/github/{{.org}}/{{.repository}}",
    "allowedRepositories": [
      "my-org/*"             // Supports exact match or wildcard (e.g. "org/*", "*")
    ],
    "requiredClaims": ["repository", "workflow"],
    "skipTokenExpiration": false,
    "jwksCacheDuration": "10m"
  },

  // Kubernetes service account token validator
  "k8sSAToken": {
    "enabled": false,
    "spiffeIdTemplate": "spiffe://example.org/k8s/{{.sub}}",
    "tls": {
      "caFile":   "/etc/spire-identity-exchange/k8s/ca.crt",    // CA to verify K8s API server
      "certFile": "/etc/spire-identity-exchange/k8s/client.crt", // Client cert for mTLS
      "keyFile":  "/etc/spire-identity-exchange/k8s/client.key"
    }
  }
}
```

At least one of `githubOIDC` or `k8sSAToken` must be enabled.

### SPIFFE ID templates

Templates use Go's `text/template` syntax. For GitHub OIDC, all JWT claims are available, along with the following pre-processed fields:

| Variable | Description |
|---|---|
| `{{.org}}` | GitHub organization (sanitized, from `repository`) |
| `{{.repository}}` | Repository name (sanitized, from `repository`) |
| `{{.ref}}` | Git ref with `refs/heads/` / `refs/tags/` prefix stripped |
| `{{.workflow}}` | Workflow name |
| `{{.actor}}` | Actor (triggering user) |
| `{{.sha}}` | Commit SHA |
| `{{.sub}}` | Token subject |

For Kubernetes SA tokens, all raw JWT claims are available directly (e.g. `{{.sub}}`, `{{index . "kubernetes.io/serviceaccount/namespace"}}`).

For a full security reference — including claim inventories, recommended encoding/gating claims, claims to avoid, canonical templates, and common anti-patterns — see [docs/spiffe-id-template-guide.md](docs/spiffe-id-template-guide.md).

## Local testing

### End-to-end testing

No GitHub Actions access needed. The mock OIDC server generates signed tokens locally and serves the JWKS endpoint.

**Prerequisites:** [SPIRE server](https://spiffe.io/docs/latest/deploying/install-server/) running locally, [grpcurl](https://github.com/fullstorydev/grpcurl) installed.

**1. Generate TLS certs for the gRPC/HTTP server (one-time):**
```bash
mkdir -p certs
openssl req -x509 -newkey rsa:4096 \
  -keyout certs/server.key -out certs/server.crt \
  -sha256 -days 365 -nodes \
  -subj "/CN=localhost" \
  -addext "subjectAltName=IP:127.0.0.1,DNS:localhost"
```

**2. Start the mock OIDC server** (in a separate terminal):
```bash
go run ./examples/mock-github-oidc --audience spire-identity-exchange
```
It prints a signed `GITHUB_TOKEN` and serves JWKS at `http://localhost:9999/.well-known/jwks`. The mock server generates a new key pair each time it starts, so always use a token from the currently running instance.

**3. Start spire-identity-exchange** (in a separate terminal):
```bash
make build
build/bin/spire-identity-exchange --config config/config.example-local.json
```
Start spire-identity-exchange **after** the mock OIDC server so the initial JWKS fetch succeeds.

**4. Mint a certificate** using the token printed in step 2:

```bash
export GITHUB_TOKEN="<token from step 2>"

# gRPC (server-side key generation — no CSR needed)
grpcurl -insecure \
  -d "{\"githubOIDC\":{\"githubToken\":\"${GITHUB_TOKEN}\"},\"serverKeyGenRequest\":{}}" \
  localhost:8443 \
  proto.spiffe.spireidentityexchange.SpireIdentityExchangeApi/MintCertificate

# HTTP gateway
curl -k -X POST https://localhost:8444/v1/mint-certificate \
  -H "Content-Type: application/json" \
  -d "{\"githubOIDC\":{\"githubToken\":\"${GITHUB_TOKEN}\"},\"serverKeyGenRequest\":{}}"
```

### Testing with a CSR (client-side key generation)

Instead of server-side key generation, you can provide your own CSR. The SPIFFE ID in the CSR must match what the server derives from the token claims using the configured `spiffeIdTemplate`. With `config.example-local.json` and the default mock token claims, the derived SPIFFE ID is:

```bash
SPIFFE_ID="spiffe://example.org/v2/github/my-enterprise/my-org-my-repo-github-workflows-mock-workflow-yml-refs-heads-main/push"

openssl req -new \
  -newkey rsa:2048 -nodes -keyout workload.key \
  -subj "/CN=workload" \
  -addext "subjectAltName=URI:${SPIFFE_ID}" \
  -out workload.csr

CSR_B64=$(openssl req -in workload.csr -outform DER | base64 | tr -d '\n')

grpcurl -insecure \
  -d "{\"githubOIDC\":{\"githubToken\":\"${GITHUB_TOKEN}\"},\"mintX509SVIDRequest\":{\"csr\":\"${CSR_B64}\"}}" \
  localhost:8443 \
  proto.spiffe.spireidentityexchange.SpireIdentityExchangeApi/MintCertificate
```

### Testing with Kubernetes Service Account tokens

```bash
K8S_TOKEN=$(kubectl create token my-service-account -n my-namespace)

grpcurl -insecure \
  -d "{\"k8sSA\":{\"k8sSAToken\":\"${K8S_TOKEN}\"},\"mintX509SVIDRequest\":{\"csr\":\"${CSR_B64}\"}}" \
  localhost:8443 \
  proto.spiffe.spireidentityexchange.SpireIdentityExchangeApi/MintCertificate
```

### Inspecting the service

```bash
# List services
grpcurl -insecure localhost:8443 list

# Describe the API
grpcurl -insecure localhost:8443 describe proto.spiffe.spireidentityexchange.SpireIdentityExchangeApi
```

## Metrics

spire-identity-exchange exposes Prometheus metrics on `metricsPort` (default `9090`):

```bash
curl http://localhost:9090/metrics
```

Key metrics:

| Metric | Description |
|---|---|
| `spire-identity-exchange_operation_duration_seconds` | Latency histogram per operation (validate_token, fetch_jwks, mint_certificate) |
| `spire-identity-exchange_operation_count_total` | Request count per operation and status code |

## Project structure

```
api/                        # Protobuf definitions and generated Go code
internal/
  config/                   # Configuration structs and validation
  const/                    # Shared constants (claim names, metric labels)
  github-oidc/              # GitHub Actions OIDC token validator
  k8s-sa-token/             # Kubernetes service account token validator
  metrics/                  # Metrics interface and Prometheus implementation
  service/                  # gRPC server, request dispatch, certificate minting
  utils/                    # JWT claim helpers, SPIFFE ID template execution
  validator/                # TokenValidator and KeySynchronizer interfaces
main.go                     # Entry point
config.example.json         # Example configuration
```

## Contributing

Contributions are welcome. Please open an issue or pull request. When adding a new authentication method:

1. Implement `validator.TokenValidator` in a new `internal/<method>/` package
2. Add a corresponding config struct in `internal/config/config.go`
3. Wire it up in `main.go` and `internal/service/`
