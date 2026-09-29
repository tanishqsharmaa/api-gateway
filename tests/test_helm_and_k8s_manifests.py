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
