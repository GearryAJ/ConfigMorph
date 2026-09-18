import io
import json
import zipfile
from pathlib import Path

import pytest
from fastapi.testclient import TestClient

from app.main import app


client=TestClient(app)
ALLOWLIST={"candidate-pan-os.set","security-rule-ordering.json","migration-report.json","review-report.json","validation-report.json","mappings.json","README"}


@pytest.mark.parametrize("vendor,version,path",[
    ("cisco_asa","9.20","examples/asa/basic.cfg"),
    ("fortigate","7.4","examples/fortigate/basic.conf"),
])
def test_release_candidate_evidence_provenance_and_export(vendor,version,path):
    source=Path(path).read_text(encoding="utf-8")
    if vendor=="cisco_asa": source=f"ASA Version {version}\n"+source+"\naccess-group outside_in in interface outside\n"
    else:
        source=f"#config-version=FGT60F-{version}.0-FW-build0000-000000:opmode=0:vdom=0:user=admin\n"+source
        source=source.replace('config system zone\n', 'config system zone\n edit "outside"\n  set interface "port1"\n next\n')
    analyzed=client.post("/api/analyze",data={"source":source,"source_vendor":vendor,"source_version":version,"target_vendor":"paloalto","target_version":"11.1"})
    assert analyzed.status_code==200
    project=analyzed.text.split("Project: <code>")[1].split("<")[0]; base=f"/api/projects/{project}/migration"
    mappings=client.get(base+"/mappings").json(); mappings["security_rule_placement"]={"mode":"BOTTOM","anchor_rule":None}
    for mapping in mappings["interfaces"]:
        outside=(mapping["source_nameif"] or mapping["source_interface"]).lower() in {"outside","port1"}
        mapping.update(target_interface="ethernet1/1" if outside else "ethernet1/2",target_zone="untrust" if outside else "trust",confirmed=True)
    assert client.put(base+"/mappings",json=mappings).status_code==200

    rendered=client.post(base+"/render"); assert rendered.status_code==200
    body=rendered.json(); report=body["report"]; candidate=body["candidate"]
    generated=[x for x in report["compatibility"] if x["status"] in {"EXACT","SUPPORTED","PARTIAL"}]
    assert generated and all(x["version_status"]=="VERIFIED" and len(x["capability_refs"])==2 and x["documentation_refs"] for x in generated)
    assert any("set address " in line for line in candidate.splitlines())
    assert any("set service " in line for line in candidate.splitlines())
    assert any("set rulebase security rules " in line for line in candidate.splitlines())
    assert any("set network virtual-router default routing-table ip static-route " in line for line in candidate.splitlines())
    assert not any(" rulebase nat rules " in line for line in candidate.splitlines())
    nat=[x for x in report["compatibility"] if x["entity_type"]=="nat_policy"]
    assert nat and all(x["status"]=="MANUAL_REVIEW" for x in nat)
    assert report["generated_entities"]+report["skipped_entities"]==report["total_entities"]
    assert report["source_version"]["detected_family"]==version
    assert report["source_version"]["selected_version"]==version and report["source_version"]["override"] is False
    assert report["target_version"]["selected_version"]=="11.1"
    assert report["documentation_refs"] and report["security_rule_ordering"]["documentation_refs"]

    validation=client.post(base+"/validate"); validation_body=validation.json()
    assert validation.status_code==200 and validation_body["status"]!="BLOCKING", validation_body
    package=client.get(base+"/review-package"); assert package.status_code==200
    with zipfile.ZipFile(io.BytesIO(package.content)) as archive:
        assert set(archive.namelist())==ALLOWLIST
        assert not ({"source.cfg","normalized.json","versions.json","compatibility.json"} & set(archive.namelist()))
        readme=archive.read("README").decode(); assert "CANDIDATE CONFIGURATION — ENGINEER REVIEW REQUIRED" in readme
        assert "PAN-OS 11.1" in readme and "No automatic deployment" in readme and "application-level" in readme
        exported=json.loads(archive.read("review-report.json")); assert exported["documentation_refs"]


def test_malformed_release_input_has_no_candidate():
    response=client.post("/api/analyze",data={"source":"not a firewall configuration","source_vendor":"auto","target_vendor":"paloalto","target_version":"11.1"})
    assert response.status_code==422
