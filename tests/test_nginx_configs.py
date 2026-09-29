import json
from pathlib import Path

import yaml


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

def test_error_pages_configmap():
    cm_path = Path("k8s/ingress/error-pages-configmap.yaml")
    assert cm_path.exists(), "error-pages-configmap.yaml missing"
    doc = yaml.safe_load(cm_path.read_text(encoding="utf-8"))
    assert doc["kind"] == "ConfigMap"
    assert doc["metadata"]["name"] == "warden-ingress-error-pages"
    data = doc.get("data", {})
    assert "401.json" in data
    assert "403.json" in data
    assert "429.json" in data
    
    # Verify 401 payload conforms to RFC 7807 schema
    p401 = json.loads(data["401.json"])
    assert p401["status"] == 401
    assert p401["error_code"] == "ERR_AUTH_ROLE_MISSING"
    assert "title" in p401 and "type" in p401

def test_rate_limiting_config():
    rate_conf = Path("config/nginx/rate-limiting.conf")
    assert rate_conf.exists(), "rate-limiting.conf missing"
    content = rate_conf.read_text(encoding="utf-8")
    assert "limit_req_zone $binary_remote_addr zone=warden_ip_limit:10m rate=50r/m;" in content
    assert "limit_req_status 429;" in content
    assert "limit_req zone=warden_ip_limit burst=10 nodelay;" in content

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



