import json

import pytest

from app.tools.pan_lab_capture import Capture, prepare


def enable(monkeypatch):
    for name in ("FCS_PAN_LAB_VALIDATION_ENABLED", "FCS_PAN_LAB_ISOLATED", "FCS_PAN_LAB_EVIDENCE_CAPTURE"):
        monkeypatch.setenv(name, "true")


def test_capture_template_is_local_sanitized_workspace(monkeypatch, tmp_path):
    enable(monkeypatch)
    ca = tmp_path / "lab-ca.pem"
    ca.write_text("test CA", encoding="utf-8")
    path = prepare(Capture.ADDRESS, "https://pan-lab.example", ca, tmp_path / "evidence")
    record = json.loads(path.read_text(encoding="utf-8"))
    assert path.name == "address.json" and (tmp_path / "evidence/raw").is_dir()
    assert record["confidence"] == "UNVERIFIED" and record["management_mode"] == "LOCAL_FIREWALL"
    assert "pan-lab.example" not in path.read_text(encoding="utf-8")


@pytest.mark.parametrize("missing", [
    "FCS_PAN_LAB_VALIDATION_ENABLED",
    "FCS_PAN_LAB_ISOLATED",
    "FCS_PAN_LAB_EVIDENCE_CAPTURE",
])
def test_every_opt_in_is_required(monkeypatch, tmp_path, missing):
    enable(monkeypatch)
    monkeypatch.delenv(missing)
    ca = tmp_path / "ca.pem"
    ca.touch()
    with pytest.raises(ValueError, match="all three"):
        prepare(Capture.SERVICE, "https://pan-lab.example", ca, tmp_path / "evidence")


@pytest.mark.parametrize("host", ["http://pan-lab.example", "https://pan-lab.example/api", "https://admin:secret@pan-lab.example", "pan-lab.example"])
def test_host_requires_tls_origin(monkeypatch, tmp_path, host):
    enable(monkeypatch)
    ca = tmp_path / "ca.pem"
    ca.touch()
    with pytest.raises(ValueError, match="HTTPS origin"):
        prepare(Capture.STATIC_ROUTE, host, ca, tmp_path / "evidence")