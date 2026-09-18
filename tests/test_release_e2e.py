import io
import zipfile
from pathlib import Path

import pytest
from fastapi.testclient import TestClient

from app.main import app


client = TestClient(app)


@pytest.mark.parametrize(
    "vendor,version,path,extra",
    [
        ("cisco_asa", "9.20", "examples/asa/basic.cfg", "\naccess-group outside_in in interface outside\n"),
        ("fortigate", "7.4", "examples/fortigate/basic.conf", ""),
    ],
)
def test_release_workflow_exposes_unverified_source_capabilities(vendor, version, path, extra):
    source = Path(path).read_text(encoding="utf-8") + extra
    analyzed = client.post("/api/analyze", data={"source": source, "source_vendor": vendor, "source_version": version, "target_vendor": "paloalto", "target_version": "11.1"})
    assert analyzed.status_code == 200
    project = analyzed.text.split("Project: <code>")[1].split("<")[0]
    base = f"/api/projects/{project}/migration"

    mappings = client.get(base + "/mappings").json()
    mappings["security_rule_placement"] = {"mode": "BOTTOM", "anchor_rule": None}
    for mapping in mappings["interfaces"]:
        mapping.update(target_interface="ethernet1/1", target_zone="untrust" if (mapping["source_nameif"] or mapping["source_interface"]).lower() in {"outside", "port1"} else "trust", confirmed=True)
    assert client.put(base + "/mappings", json=mappings).status_code == 200

    rendered = client.post(base + "/render")
    assert rendered.status_code == 200
    report = rendered.json()["report"]
    unverified = [item for item in report["compatibility"] if item["entity_type"] in {"address", "address_group", "service", "service_group", "route"}]
    assert unverified and all(item["status"] == "MANUAL_REVIEW" and item["version_status"] == "VERSION_NOT_VERIFIED" for item in unverified)
    nat = [item for item in report["compatibility"] if item["entity_type"] == "nat_policy"]
    assert nat and all(item["status"] == "MANUAL_REVIEW" for item in nat)
    assert not any(" rulebase nat rules " in line for line in rendered.json()["candidate"].splitlines())
    assert report["generated_entities"] + report["skipped_entities"] == report["total_entities"]

    validation = client.post(base + "/validate")
    assert validation.status_code == 200
    package = client.get(base + "/review-package")
    if validation.json()["status"] == "BLOCKING":
        assert package.status_code == 409
    else:
        assert package.status_code == 200
        with zipfile.ZipFile(io.BytesIO(package.content)) as archive:
            assert set(archive.namelist()) == {"candidate-pan-os.set", "migration-report.json", "review-report.json", "validation-report.json", "mappings.json", "README"}
            assert "CANDIDATE CONFIGURATION — ENGINEER REVIEW REQUIRED" in archive.read("README").decode()