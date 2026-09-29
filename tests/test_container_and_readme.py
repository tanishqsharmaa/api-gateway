from pathlib import Path


def test_dockerfile_and_compose_exist():
    assert Path("docker/Dockerfile.gateway").exists(), "docker/Dockerfile.gateway missing"
    assert Path("docker-compose.yml").exists(), "docker-compose.yml missing"
    assert Path("README.md").exists(), "README.md missing"
    
    dockerfile = Path("docker/Dockerfile.gateway").read_text(encoding="utf-8")
    assert "nginx:1.25.4-alpine" in dockerfile, "Must use nginx:1.25.4-alpine base"
    assert "EXPOSE 80" in dockerfile or "EXPOSE 80 443" in dockerfile
    
    compose = Path("docker-compose.yml").read_text(encoding="utf-8")
    assert "api-gateway" in compose
    assert "8080:80" in compose or "80:80" in compose
    
    readme = Path("README.md").read_text(encoding="utf-8")
    assert "Project Warden" in readme
    assert "GATE-6" in readme
    assert "verify_gateway_proxy.sh" in readme
    assert "X-User-Role" in readme
