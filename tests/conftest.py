from pathlib import Path
import pytest

@pytest.fixture
def project_root() -> Path:
    return Path(__file__).resolve().parent.parent

@pytest.fixture
def config_dir(project_root: Path) -> Path:
    return project_root / "config" / "nginx"

@pytest.fixture
def k8s_dir(project_root: Path) -> Path:
    return project_root / "k8s" / "ingress"
