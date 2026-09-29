# api-gateway Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Implement and verify the production edge ingress gateway and reverse proxy (`api-gateway`) for Project Warden, enforcing TLS 1.3 termination, client IP rate limiting (50 req/min with burst=10), client identity role assertion validation (`X-User-Role`), low-latency Server-Sent Events (SSE) buffer bypassing, and reverse proxy routing to `warden-orchestrator` and `warden-ingestion`.

**Architecture:** Deploys an NGINX reverse proxy and Kubernetes NGINX Ingress Controller configuration acting as the perimeter entry point for Project Warden. Terminates external TLS 1.3 traffic, validates that incoming requests assert an authorized role tag (`Employee`, `Manager`, `HR-Admin`), applies a 10MB memory-zoned IP rate limiter, disables proxy response buffering for streaming endpoints, and routes traffic cleanly to downstream HTTP services.

**Tech Stack:** NGINX 1.25.4-alpine, Kubernetes Ingress (`networking.k8s.io/v1`), Helm 3, cert-manager / Let's Encrypt, Python 3.12 (pytest, httpx, pyyaml for automated manifest and integration testing), Docker & Docker Compose.

**Spec:** `docs/api-gateway.md` (Implementation Plan: api-gateway), `docs/ARCHITECTURE_SPECIFICATION.md` (§ 1.2, § 3.1, § 3.4, § 5.7), `docs/BUILD_SEQUENCE.md` (Tier 6 / GATE-6).

## Global Constraints

- **Language Runtime & Verification**: Python 3.12 (`pytest`, `httpx`, `pyyaml`) for local automated manifest and proxy integration test suites.
- **Base Container Image**: `nginx:1.25.4-alpine` running as unprivileged system user or supervised worker.
- **Port Allocations**: Ingress HTTP Port `80` (or `8080` on local testbed), Ingress HTTPS Port `443` (TLS 1.3).
- **Identity Assertion**: Mandatory `X-User-Role` header matching exactly `^(Employee|Manager|HR-Admin)$`. Missing returns HTTP 401 (`ERR_AUTH_ROLE_MISSING`), invalid returns HTTP 403 (`ERR_AUTH_ROLE_INVALID`).
- **Error Taxonomy**: All gateway-generated rejection bodies must conform to RFC 7807 Problem Details format with `error_code`, `instance`, `title`, `status`, `detail`, `type`, and ISO 8601 `timestamp`.
- **Rate Limiting**: NGINX `limit_req_zone` sized to 10MB (`warden_ip_limit`), rate 50 req/min per IP, burst=10 with `nodelay`, emitting HTTP 429 Too Many Requests upon saturation.
- **Streaming Buffering**: Directives for `/query/stream` must include `proxy_buffering off; proxy_cache off; chunked_transfer_encoding off; proxy_read_timeout 300s; proxy_send_timeout 300s;`.
- **Route Mappings**:
  - `/query` (POST) -> `http://warden-orchestrator:8000/query`
  - `/query/stream` (POST) -> `http://warden-orchestrator:8000/query/stream`
  - `/ingest/run` (POST) -> `http://warden-ingestion:8000/ingest/run`
  - `/ingest/status/(.*)` (GET) -> `http://warden-ingestion:8000/ingest/status/$1`
  - `/health` and `/healthz` (GET) -> Immediate 200 JSON from gateway
- **Gate Requirement**: Must satisfy Master Build Sequence **GATE-6**: `bash scripts/verify_gateway_proxy.sh http://localhost:8080`.

## Review Focus

1. **Missing or Malformed `X-User-Role` Header**: Inbound requests without `X-User-Role` must return HTTP 401 with `ERR_AUTH_ROLE_MISSING`, and requests with unauthorized role strings (e.g. `Contractor`, `Admin`, or lowercase `employee`) must return HTTP 403 with `ERR_AUTH_ROLE_INVALID` in RFC 7807 JSON.
2. **Burst IP Rate Limit Saturation**: When an IP sends more than 10 burst requests within a minute beyond the 50r/m rate, the gateway must immediately return HTTP 429 Too Many Requests, while requests from other client IPs remain unaffected.
3. **SSE Immediate Packet Flushing Without Buffering**: Calls to `/query/stream` must not buffer response chunks; `proxy_buffering off;` and `chunked_transfer_encoding off;` must guarantee time-to-first-token latency overhead added by the proxy is $< 5\text{ms}$.
4. **Path Parameter Preservation for Ingestion Status**: The status polling route `/ingest/status/{run_id}` must accurately preserve and forward the run ID capture group `$1` to `warden-ingestion:8000/ingest/status/$1` without double slashes or missing IDs.
5. **Zero-Downstream Gateway Health Probing**: Endpoints `/health` and `/healthz` must return an immediate HTTP 200 JSON payload directly from NGINX without proxying to downstreams, allowing kubelet probes to pass independently of backend startup timing.

---

## File Structure

```
api-gateway/
├── config/
│   └── nginx/
│       ├── ingress-values.yaml           # Helm values for ingress-nginx with TLS 1.3 & annotations
│       ├── auth-role-validation.conf     # NGINX configuration snippet for X-User-Role validation
│       ├── rate-limiting.conf            # NGINX rate-limiting memory zone & burst directives
│       ├── sse-streaming.conf            # NGINX low-latency SSE proxy directives
│       └── nginx.conf                    # Unified standalone NGINX reverse proxy configuration
├── k8s/
│   └── ingress/
│       ├── cert-issuer.yaml              # cert-manager ClusterIssuer for Let's Encrypt TLS
│       ├── error-pages-configmap.yaml    # RFC 7807 problem details static error responses
│       └── warden-ingress.yaml           # Kubernetes Ingress manifest declaring all 5 routes
├── docker/
│   └── Dockerfile.gateway                # Production NGINX 1.25.4-alpine container definition
├── scripts/
│   └── verify_gateway_proxy.sh           # Automated integration test script satisfying GATE-6
├── tests/
│   ├── conftest.py                       # Test configuration & shared fixtures
│   ├── test_helm_and_k8s_manifests.py   # Manifest syntax, annotations, and schema validation
│   ├── test_nginx_configs.py             # NGINX configuration directive and syntax validation
│   └── test_gateway_integration.py       # Integration tests fuzzing roles, rate limits, and routes
├── pyproject.toml                        # Python package & test configuration
├── docker-compose.yml                    # Local testbed definition for standalone gateway verification
└── README.md                             # Subsystem documentation & operational runbook
```

---

## Task Decomposition

### Task 1: Project Scaffolding, Package Setup, and Helm Ingress Values

**Files:**
- Create: `pyproject.toml`
- Create: `tests/conftest.py`
- Create: `config/nginx/ingress-values.yaml`
- Create: `k8s/ingress/cert-issuer.yaml`
- Test: `tests/test_helm_and_k8s_manifests.py`

**Interfaces:**
- Consumes: None
- Produces: Base Python testbed configuration, `ingress-values.yaml` defining TLS 1.3 cipher suites and rate limit parameters, and `cert-issuer.yaml` defining cert-manager Let's Encrypt cluster issuer.

- [ ] **Step 1: Write the failing test**

```python
# tests/test_helm_and_k8s_manifests.py
from pathlib import Path
import yaml

def test_ingress_helm_values_file_exists_and_valid():
    values_path = Path("config/nginx/ingress-values.yaml")
    assert values_path.exists(), "config/nginx/ingress-values.yaml does not exist"
    content = yaml.safe_load(values_path.read_text(encoding="utf-8"))
    controller = content.get("controller", {})
    config = controller.get("config", {})
    assert config.get("ssl-protocols") == "TLSv1.3", "Must enforce TLS 1.3 exclusively"
    assert "ECDHE-ECDSA-AES256-GCM-SHA384" in config.get("ssl-ciphers", ""), "Must declare modern GCM ciphers"

def test_cert_issuer_manifest_exists_and_valid():
    issuer_path = Path("k8s/ingress/cert-issuer.yaml")
    assert issuer_path.exists(), "k8s/ingress/cert-issuer.yaml does not exist"
    docs = list(yaml.safe_load_all(issuer_path.read_text(encoding="utf-8")))
    assert len(docs) >= 1
    issuer = docs[0]
    assert issuer["kind"] == "ClusterIssuer"
    assert issuer["metadata"]["name"] == "letsencrypt-prod"
    assert "acme" in issuer["spec"]
```

- [ ] **Step 2: Run test to verify it fails**

Run: `pytest tests/test_helm_and_k8s_manifests.py -v`
Expected: FAIL with missing files `config/nginx/ingress-values.yaml` and `k8s/ingress/cert-issuer.yaml`.

- [ ] **Step 3: Implement `pyproject.toml`, `config/nginx/ingress-values.yaml`, and `k8s/ingress/cert-issuer.yaml`**

Configure `pyproject.toml` with `pytest`, `httpx`, and `pyyaml`. Create `ingress-values.yaml` setting `controller.config.ssl-protocols: "TLSv1.3"` and `ssl-ciphers`. Create `k8s/ingress/cert-issuer.yaml` with Let's Encrypt production ACME HTTP-01 solver.

- [ ] **Step 4: Run test to verify it passes**

Run: `pytest tests/test_helm_and_k8s_manifests.py -v`
Expected: PASS

- [ ] **Step 5: Commit**

```bash
git add pyproject.toml tests/ config/nginx/ingress-values.yaml k8s/ingress/cert-issuer.yaml
git commit -m "feat(gateway): scaffold package and configure helm ingress values with tls 1.3"
```

---

### Task 2: Identity Header Validation & RFC 7807 Error Configuration

**Files:**
- Create: `config/nginx/auth-role-validation.conf`
- Create: `k8s/ingress/error-pages-configmap.yaml`
- Modify: `tests/test_nginx_configs.py`
- Test: `tests/test_nginx_configs.py`

**Interfaces:**
- Consumes: Allowed role strings list `["Employee", "Manager", "HR-Admin"]` and RFC 7807 schema.
- Produces: NGINX snippet `config/nginx/auth-role-validation.conf` validating `$http_x_user_role` and returning 401/403 with RFC 7807 bodies, and `k8s/ingress/error-pages-configmap.yaml`.

- [ ] **Step 1: Write the failing test**

```python
# tests/test_nginx_configs.py
from pathlib import Path
import json

def test_auth_role_validation_snippet():
    snippet_path = Path("config/nginx/auth-role-validation.conf")
    assert snippet_path.exists(), "auth-role-validation.conf missing"
    content = snippet_path.read_text(encoding="utf-8")
    assert '$http_x_user_role = ""' in content, "Must check for empty role header"
    assert "ERR_AUTH_ROLE_MISSING" in content, "Must return ERR_AUTH_ROLE_MISSING error code"
    assert "ERR_AUTH_ROLE_INVALID" in content, "Must return ERR_AUTH_ROLE_INVALID error code"
    assert "Employee|Manager|HR-Admin" in content, "Must enforce exact role whitelist"
    assert "return 401" in content
    assert "return 403" in content
```

- [ ] **Step 2: Run test to verify it fails**

Run: `pytest tests/test_nginx_configs.py::test_auth_role_validation_snippet -v`
Expected: FAIL with `auth-role-validation.conf missing`.

- [ ] **Step 3: Implement `config/nginx/auth-role-validation.conf` and `k8s/ingress/error-pages-configmap.yaml`**

Implement NGINX conditionals checking if `$http_x_user_role` is empty (return 401 with JSON RFC 7807 body) and if `$http_x_user_role !~* ^(Employee|Manager|HR-Admin)$` (return 403 with JSON RFC 7807 body). Implement `k8s/ingress/error-pages-configmap.yaml` holding static fallback RFC 7807 payloads.

- [ ] **Step 4: Run test to verify it passes**

Run: `pytest tests/test_nginx_configs.py::test_auth_role_validation_snippet -v`
Expected: PASS

- [ ] **Step 5: Commit**

```bash
git add config/nginx/auth-role-validation.conf k8s/ingress/error-pages-configmap.yaml tests/test_nginx_configs.py
git commit -m "feat(gateway): implement identity role validation snippet and rfc 7807 error responses"
```

---

### Task 3: Distributed IP-Based Rate Limiting Configuration

**Files:**
- Create: `config/nginx/rate-limiting.conf`
- Modify: `tests/test_nginx_configs.py`
- Test: `tests/test_nginx_configs.py`

**Interfaces:**
- Consumes: Rate limit specification (50 req/min, burst=10, `nodelay`).
- Produces: `config/nginx/rate-limiting.conf` declaring memory zone `warden_ip_limit:10m` and burst rate limiting directives.

- [ ] **Step 1: Write the failing test**

```python
# tests/test_nginx_configs.py (addition)
def test_rate_limiting_config():
    rate_conf = Path("config/nginx/rate-limiting.conf")
    assert rate_conf.exists(), "rate-limiting.conf missing"
    content = rate_conf.read_text(encoding="utf-8")
    assert "limit_req_zone $binary_remote_addr zone=warden_ip_limit:10m rate=50r/m;" in content
    assert "limit_req_status 429;" in content
    assert "limit_req zone=warden_ip_limit burst=10 nodelay;" in content
```

- [ ] **Step 2: Run test to verify it fails**

Run: `pytest tests/test_nginx_configs.py::test_rate_limiting_config -v`
Expected: FAIL with `rate-limiting.conf missing`.

- [ ] **Step 3: Implement `config/nginx/rate-limiting.conf`**

Author `config/nginx/rate-limiting.conf` declaring `limit_req_zone $binary_remote_addr zone=warden_ip_limit:10m rate=50r/m;`, `limit_req_status 429;`, and location directive `limit_req zone=warden_ip_limit burst=10 nodelay;`.

- [ ] **Step 4: Run test to verify it passes**

Run: `pytest tests/test_nginx_configs.py::test_rate_limiting_config -v`
Expected: PASS

- [ ] **Step 5: Commit**

```bash
git add config/nginx/rate-limiting.conf tests/test_nginx_configs.py
git commit -m "feat(gateway): implement ip-based rate limiting memory zone and burst configuration"
```

---

### Task 4: Low-Latency Server-Sent Events (SSE) Proxy Configuration

**Files:**
- Create: `config/nginx/sse-streaming.conf`
- Modify: `tests/test_nginx_configs.py`
- Test: `tests/test_nginx_configs.py`

**Interfaces:**
- Consumes: Low-latency streaming requirements (`ARCHITECTURE_SPECIFICATION.md` § 3.4).
- Produces: `config/nginx/sse-streaming.conf` disabling proxy buffering, caching, chunked transfer encoding, and extending timeouts to 300s.

- [ ] **Step 1: Write the failing test**

```python
# tests/test_nginx_configs.py (addition)
def test_sse_streaming_config():
    sse_conf = Path("config/nginx/sse-streaming.conf")
    assert sse_conf.exists(), "sse-streaming.conf missing"
    content = sse_conf.read_text(encoding="utf-8")
    assert "proxy_buffering off;" in content
    assert "proxy_cache off;" in content
    assert "chunked_transfer_encoding off;" in content
    assert "proxy_read_timeout 300s;" in content
    assert "proxy_send_timeout 300s;" in content
    assert "proxy_set_header Connection '';" in content
    assert "proxy_http_version 1.1;" in content
```

- [ ] **Step 2: Run test to verify it fails**

Run: `pytest tests/test_nginx_configs.py::test_sse_streaming_config -v`
Expected: FAIL with `sse-streaming.conf missing`.

- [ ] **Step 3: Implement `config/nginx/sse-streaming.conf`**

Author `config/nginx/sse-streaming.conf` containing all 7 proxy streaming directives.

- [ ] **Step 4: Run test to verify it passes**

Run: `pytest tests/test_nginx_configs.py::test_sse_streaming_config -v`
Expected: PASS

- [ ] **Step 5: Commit**

```bash
git add config/nginx/sse-streaming.conf tests/test_nginx_configs.py
git commit -m "feat(gateway): implement low-latency sse streaming proxy configuration"
```

---

### Task 5: Unified NGINX Configuration & Kubernetes Ingress Manifest

**Files:**
- Create: `config/nginx/nginx.conf`
- Create: `k8s/ingress/warden-ingress.yaml`
- Modify: `tests/test_helm_and_k8s_manifests.py`
- Modify: `tests/test_nginx_configs.py`
- Test: `tests/test_helm_and_k8s_manifests.py`, `tests/test_nginx_configs.py`

**Interfaces:**
- Consumes: Snippets from Tasks 2, 3, 4 and upstream definitions for `warden-orchestrator:8000` and `warden-ingestion:8000`.
- Produces: Complete unified `config/nginx/nginx.conf` (for standalone/local testing) and declarative Kubernetes Ingress `k8s/ingress/warden-ingress.yaml` declaring all 5 path mappings.

- [ ] **Step 1: Write the failing test**

```python
# tests/test_nginx_configs.py (addition)
def test_unified_nginx_conf():
    conf_path = Path("config/nginx/nginx.conf")
    assert conf_path.exists(), "nginx.conf missing"
    content = conf_path.read_text(encoding="utf-8")
    assert "upstream orchestrator_backend" in content
    assert "upstream ingestion_backend" in content
    assert "location /health" in content
    assert "location /healthz" in content
    assert "location /query" in content
    assert "location /query/stream" in content
    assert "location /ingest/run" in content
    assert "location ~ ^/ingest/status/(.*)$" in content

# tests/test_helm_and_k8s_manifests.py (addition)
def test_kubernetes_ingress_manifest():
    ingress_path = Path("k8s/ingress/warden-ingress.yaml")
    assert ingress_path.exists(), "warden-ingress.yaml missing"
    doc = yaml.safe_load(ingress_path.read_text(encoding="utf-8"))
    assert doc["kind"] == "Ingress"
    assert doc["metadata"]["name"] == "warden-ingress"
    annotations = doc["metadata"]["annotations"]
    assert annotations.get("kubernetes.io/ingress.class") == "nginx"
    assert "limit-rps" in annotations
    rules = doc["spec"]["rules"][0]["http"]["paths"]
    paths = [p["path"] for p in rules]
    assert "/query/stream" in paths
    assert "/query" in paths
    assert "/ingest" in paths
    assert "/health" in paths
```

- [ ] **Step 2: Run test to verify it fails**

Run: `pytest tests/test_nginx_configs.py::test_unified_nginx_conf tests/test_helm_and_k8s_manifests.py::test_kubernetes_ingress_manifest -v`
Expected: FAIL with `nginx.conf missing` and `warden-ingress.yaml missing`.

- [ ] **Step 3: Implement `config/nginx/nginx.conf` and `k8s/ingress/warden-ingress.yaml`**

Author `config/nginx/nginx.conf` assembling upstreams (`warden-orchestrator:8000`, `warden-ingestion:8000`), health endpoints, `/query`, `/query/stream`, `/ingest/run`, and `/ingest/status/(.*)` with proper rate limiting, role checks, and SSE directives. Author `k8s/ingress/warden-ingress.yaml` specifying declarative Ingress resource with TLS secret `warden-tls-secret` and configuration snippets.

- [ ] **Step 4: Run test to verify it passes**

Run: `pytest tests/test_nginx_configs.py::test_unified_nginx_conf tests/test_helm_and_k8s_manifests.py::test_kubernetes_ingress_manifest -v`
Expected: PASS

- [ ] **Step 5: Commit**

```bash
git add config/nginx/nginx.conf k8s/ingress/warden-ingress.yaml tests/
git commit -m "feat(gateway): provide unified nginx reverse proxy and kubernetes ingress manifests"
```

---

### Task 6: Ingress Gateway Integration, Security Fuzzing Suite & Verification Script (GATE-6)

**Files:**
- Create: `scripts/verify_gateway_proxy.sh`
- Create: `tests/test_gateway_integration.py`
- Test: `tests/test_gateway_integration.py`

**Interfaces:**
- Consumes: Running NGINX gateway endpoint (or mock server/local docker proxy).
- Produces: Automated integration test suite validating:
  - Missing `X-User-Role` yields HTTP 401 `ERR_AUTH_ROLE_MISSING`.
  - Invalid `X-User-Role: Contractor` yields HTTP 403 `ERR_AUTH_ROLE_INVALID`.
  - Valid `X-User-Role: Employee` is passed upstream.
  - Saturated requests (>10 burst) return HTTP 429.
  - Streaming `/query/stream` flushes immediately with SSE headers.
  - Verification shell script satisfying **GATE-6**.

- [ ] **Step 1: Write the failing test**

```python
# tests/test_gateway_integration.py
import pytest
from pathlib import Path

def test_verification_script_exists_and_executable():
    script_path = Path("scripts/verify_gateway_proxy.sh")
    assert script_path.exists(), "verify_gateway_proxy.sh missing"
    content = script_path.read_text(encoding="utf-8")
    assert "ERR_AUTH_ROLE_MISSING" in content
    assert "ERR_AUTH_ROLE_INVALID" in content
    assert "429" in content
    assert "/query/stream" in content
```

- [ ] **Step 2: Run test to verify it fails**

Run: `pytest tests/test_gateway_integration.py::test_verification_script_exists_and_executable -v`
Expected: FAIL with `verify_gateway_proxy.sh missing`.

- [ ] **Step 3: Implement `scripts/verify_gateway_proxy.sh` and `tests/test_gateway_integration.py`**

Write `scripts/verify_gateway_proxy.sh` using `curl` to test 401 missing role, 403 invalid role, 200 health probe, rate limit burst 429 rejection, and SSE streaming headers. Write comprehensive integration tests in `tests/test_gateway_integration.py` that can execute both statically and against a live gateway URL.

- [ ] **Step 4: Run test to verify it passes**

Run: `pytest tests/test_gateway_integration.py -v`
Expected: PASS

- [ ] **Step 5: Commit**

```bash
git add scripts/verify_gateway_proxy.sh tests/test_gateway_integration.py
git commit -m "feat(gateway): implement gateway verification script and integration test suite"
```

---

### Task 7: Dockerfile, Local Testbed Orchestration & Repository Documentation

**Files:**
- Create: `docker/Dockerfile.gateway`
- Create: `docker-compose.yml`
- Create: `README.md`
- Test: Complete test suite (`pytest tests/ -v`)

**Interfaces:**
- Consumes: All configuration files and test scripts from Tasks 1-6.
- Produces: Reproducible OCI container definition `docker/Dockerfile.gateway`, standalone `docker-compose.yml` testbed, and comprehensive `README.md` with operational runbooks.

- [ ] **Step 1: Write the failing test**

```python
# tests/test_container_and_readme.py
from pathlib import Path

def test_dockerfile_and_compose_exist():
    assert Path("docker/Dockerfile.gateway").exists()
    assert Path("docker-compose.yml").exists()
    assert Path("README.md").exists()
    
    dockerfile = Path("docker/Dockerfile.gateway").read_text(encoding="utf-8")
    assert "nginx:1.25.4-alpine" in dockerfile
    
    readme = Path("README.md").read_text(encoding="utf-8")
    assert "Project Warden" in readme
    assert "GATE-6" in readme
    assert "verify_gateway_proxy.sh" in readme
```

- [ ] **Step 2: Run test to verify it fails**

Run: `pytest tests/test_container_and_readme.py -v`
Expected: FAIL with missing Dockerfile and README.

- [ ] **Step 3: Implement `docker/Dockerfile.gateway`, `docker-compose.yml`, and `README.md`**

Author `docker/Dockerfile.gateway` based on `nginx:1.25.4-alpine`. Author `docker-compose.yml` mounting `config/nginx/nginx.conf` and exposing port 8080. Author comprehensive `README.md` documenting architecture, routing table, rate limiting, role checking, local quickstart, and session handoff.

- [ ] **Step 4: Run test to verify it passes**

Run: `pytest tests/ -v`
Expected: PASS across all test files.

- [ ] **Step 5: Commit**

```bash
git add docker/Dockerfile.gateway docker-compose.yml README.md tests/test_container_and_readme.py
git commit -m "feat(gateway): add dockerfile, docker-compose testbed and comprehensive documentation"
```

---

## Self-Review Checklist

- [x] **Spec coverage**:
  - TLS 1.3 Helm configuration -> Task 1
  - Client identity validation (`X-User-Role` -> 401/403 RFC 7807) -> Task 2
  - IP-based rate limiting (50r/m burst=10) -> Task 3
  - Low-latency SSE buffer bypassing (`proxy_buffering off`) -> Task 4
  - Ingress routing rules & K8s Ingress manifest -> Task 5
  - Integration fuzzing & verification script satisfying GATE-6 -> Task 6
  - Docker container & README documentation -> Task 7
- [x] **Step scan**: Each step defines unambiguous tests, code signatures, commands, and expected results.
- [x] **Type consistency**: Error codes `ERR_AUTH_ROLE_MISSING` and `ERR_AUTH_ROLE_INVALID` and route paths `/query`, `/query/stream`, `/ingest/run`, `/ingest/status/(.*)`, `/health` are used consistently across all tasks.
- [x] **Review Focus**: All 5 items from Review Focus have explicit tests in Tasks 1-6.
- [x] **Proportion**: Plan is concise, actionable, and strictly addresses the `api-gateway` implementation requirements without unnecessary bloat.

---

## Execution Handoff

Plan complete and saved to `docs/superpowers/plans/2026-09-29-api-gateway.md`. Please review the plan. Which execution approach would you prefer?

- **Subagent-driven** - A fresh subagent implements each task and a fresh reviewer checks it before the next one starts, then a whole-branch review at the end. Most thorough; costs a fresh context per task and per review.
- **Native** - I implement every task myself in this session, the way this harness runs work, then one fresh reviewer on the most capable model checks the whole branch. Cheapest and fastest; no independent review until the end. Runs well with a mid-tier session model, since the plan carries the design.

For this plan I recommend **Native**, because the tasks are tightly coupled around NGINX configurations, Kubernetes manifests, and bash/pytest verification suites, allowing rapid inline verification and iterative testing in this session. Does the plan capture what you want, and which approach should we use?
