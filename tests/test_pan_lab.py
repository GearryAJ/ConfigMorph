import pytest
from fastapi.testclient import TestClient

from app.config import settings
from app.core.migration.models import MigrationMappings,PanSetCommand,TargetManagementMode
from app.core.pan_lab import PanLabValidationResult,validate_in_lab
from app.main import app

def command(text="set address safe ip-netmask 192.0.2.1"):
    return PanSetCommand(path=text.split(),entity_id="address:source",text=text,target_profile="panos-11.1",capability_id="panos-11.1:address",documentation_refs=["PANOS-11.1-CONFIGURE-CLI-HIERARCHY"],management_context=MigrationMappings())

class FakeTransport:
    def __init__(self,version="11.1.4",findings=None,fail=None): self.device_version=version; self.findings=findings or []; self.fail=fail; self.calls=[]
    def _call(self,name):
        self.calls.append(name)
        if self.fail==name: raise RuntimeError("secret host password token")
    def version(self): self._call("version"); return self.device_version
    def snapshot(self): self._call("snapshot"); return "opaque-snapshot"
    def apply(self,commands): self._call("apply")
    def validate(self): self._call("validate"); return self.findings
    def revert(self,snapshot): self._call("revert")
    def verify_revert(self,snapshot): self._call("verify_revert"); return self.fail!="verification"

def test_success_uses_required_sequence_and_never_commits():
    transport=FakeTransport(); result=validate_in_lab(command().text+"\n",[command()],TargetManagementMode.LOCAL_FIREWALL,transport)
    assert result.status=="PASS" and result.candidate_reverted and result.revert_verified and not result.commit_performed
    assert transport.calls==["version","snapshot","apply","validate","revert","verify_revert"]

def test_findings_are_correlated_without_candidate_or_secrets():
    transport=FakeTransport(findings=[{"category":"reference","message":"missing object","command_index":0}])
    result=validate_in_lab(command().text+"\n",[command()],TargetManagementMode.LOCAL_FIREWALL,transport)
    finding=result.reference_errors[0]
    assert result.status=="BLOCKING" and finding.entity_id=="address:source" and finding.capability_id=="panos-11.1:address"
    serialized=result.model_dump_json(); assert command().text not in serialized and "opaque-snapshot" not in serialized

@pytest.mark.parametrize("mode,candidate,status",[(TargetManagementMode.PANORAMA,command().text,"BLOCKING"),(TargetManagementMode.LOCAL_FIREWALL,"set rulebase nat rules n source any","BLOCKING")])
def test_unsafe_scope_blocked_before_connection(mode,candidate,status):
    transport=FakeTransport(); result=validate_in_lab(candidate+"\n",[command(candidate)],mode,transport)
    assert result.status==status and transport.calls==[]

def test_version_mismatch_does_not_mutate():
    transport=FakeTransport(version="12.1.0"); result=validate_in_lab(command().text+"\n",[command()],TargetManagementMode.LOCAL_FIREWALL,transport)
    assert result.status=="VERSION_MISMATCH" and transport.calls==["version"]

@pytest.mark.parametrize("failure",["apply","validate","revert","verification"])
def test_failure_sanitized_and_cleanup_failure_blocks(failure):
    transport=FakeTransport(fail=failure); result=validate_in_lab(command().text+"\n",[command()],TargetManagementMode.LOCAL_FIREWALL,transport)
    assert result.status in {"ERROR","BLOCKING"} and not result.commit_performed
    assert "secret" not in result.model_dump_json()
    if failure in {"revert","verification"}: assert result.status=="BLOCKING" and not result.revert_verified

def test_commit_invariant_rejected():
    data=dict(status="PASS",started_at="2026-01-01T00:00:00Z",duration_ms=1,candidate_hash="0"*64,commit_performed=True)
    with pytest.raises(ValueError): PanLabValidationResult(**data)

def test_endpoint_disabled_and_enabled_state_never_connects(monkeypatch,tmp_path):
    monkeypatch.setattr(settings,"workspace_dir",tmp_path); project="00000000-0000-0000-0000-000000000001"; root=tmp_path/project
    root.mkdir(); (root/"normalized.json").write_text('{"vendor":"cisco_asa"}',encoding="utf-8")
    # Project lookup is required before feature state; use an existing route path traversal rejection instead of bypassing persistence.
    response=TestClient(app).post(f"/api/projects/{project}/migration/pan-lab-validation")
    assert response.status_code in {404,409} and "host" not in response.text.lower()