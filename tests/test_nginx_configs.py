from pathlib import Path
import json
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

