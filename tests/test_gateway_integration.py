from pathlib import Path
import json
import pytest

def test_verification_script_exists_and_valid():
    script_path = Path("scripts/verify_gateway_proxy.sh")
    assert script_path.exists(), "scripts/verify_gateway_proxy.sh missing"
    content = script_path.read_text(encoding="utf-8")
    assert "ERR_AUTH_ROLE_MISSING" in content, "Must verify 401 ERR_AUTH_ROLE_MISSING"
    assert "ERR_AUTH_ROLE_INVALID" in content, "Must verify 403 ERR_AUTH_ROLE_INVALID"
    assert "429" in content, "Must verify rate-limit 429 status code"
    assert "/query/stream" in content, "Must verify SSE streaming endpoint"
    assert "/health" in content, "Must verify health check probe"

def test_gateway_config_consistency():
    conf_path = Path("config/nginx/nginx.conf")
    content = conf_path.read_text(encoding="utf-8")
    
    # Verify rate limit zone settings
    assert "zone=warden_ip_limit:10m rate=50r/m;" in content
    assert "limit_req zone=warden_ip_limit burst=10 nodelay;" in content
    assert "limit_req_status 429;" in content
    
    # Verify SSE directives
    assert "proxy_buffering off;" in content
    assert "chunked_transfer_encoding off;" in content
    assert "proxy_read_timeout 300s;" in content

def test_rfc7807_error_payload_structures():
    # Verify JSON structure embedded inside NGINX configuration
    conf_path = Path("config/nginx/nginx.conf")
    content = conf_path.read_text(encoding="utf-8")
    
    # Extract 401 JSON
    idx401 = content.find("return 401 '") + len("return 401 '")
    end401 = content.find("';", idx401)
    json401 = json.loads(content[idx401:end401])
    assert json401["status"] == 401
    assert json401["error_code"] == "ERR_AUTH_ROLE_MISSING"
    assert json401["type"] == "https://warden.enterprise/errors/auth-role-missing"
    
    # Extract 403 JSON
    idx403 = content.find("return 403 '") + len("return 403 '")
    end403 = content.find("';", idx403)
    json403 = json.loads(content[idx403:end403])
    assert json403["status"] == 403
    assert json403["error_code"] == "ERR_AUTH_ROLE_INVALID"
    assert json403["type"] == "https://warden.enterprise/errors/auth-role-invalid"
