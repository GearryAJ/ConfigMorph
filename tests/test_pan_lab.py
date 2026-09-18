from datetime import datetime, timezone

import pytest
from fastapi.testclient import TestClient

from app.config import settings
from app.core.migration.models import MigrationMappings,PanSetCommand,TargetManagementMode
from app.core.pan_lab import PanLabOperation,PanLabValidationResult,assert_safe_request,snapshot_name,validate_in_lab
from app.main import app

def command(text="set address safe ip-netmask 192.0.2.1"):
    return PanSetCommand(path=text.split(),entity_id="address:source",text=text,target_profile="panos-11.1",capability_id="panos-11.1:address",documentation_refs=["PANOS-11.1-CONFIGURE-CLI-HIERARCHY"],management_context=MigrationMappings())

class FakeTransport:
    def __init__(self,version="11.1.4",findings=None,fail=None):
        self.device_version=version; self.findings=findings or []; self.fail=fail; self.calls=[]; self.state="running-plus-existing-candidate"; self.saved=None
    def _call(self,name):
        self.calls.append(name)
        if self.fail==name: raise RuntimeError("secret host password token")
    def version(self): self._call("version"); return self.device_version
    def candidate_state(self):
        self._call("candidate_state")
        return "mismatch" if self.fail=="verification" and self.saved is not None and self.state==self.saved else self.state
    def save_candidate(self,name): self._call("save_candidate"); self.saved=self.state
    def verify_snapshot(self,name): self._call("verify_snapshot"); return self.fail!="snapshot_verification"
    def apply(self,commands):
        self._call("apply"); self.state+="+convert-in"
        if self.fail=="partial_apply": raise ConnectionError("secret host password token")
    def validate(self): self._call("validate"); return self.findings
    def load_snapshot(self,name): self._call("load_snapshot"); self.state=self.saved

def run(transport): return validate_in_lab(command().text+"\n",[command()],TargetManagementMode.LOCAL_FIREWALL,transport)

def test_pass_restores_preexisting_candidate_and_never_commits():
    transport=FakeTransport(); result=run(transport)
    assert result.status=="PASS" and result.cleanup_status=="RESTORED" and result.preexisting_candidate_preserved
    assert result.snapshot_created and result.restore_attempted and result.restore_succeeded and result.restore_verified and not result.commit_performed
    assert transport.state=="running-plus-existing-candidate"
    assert transport.calls==["version","candidate_state","save_candidate","verify_snapshot","apply","validate","load_snapshot","candidate_state"]

def test_findings_are_correlated_then_restored():
    result=run(FakeTransport(findings=[{"category":"reference","message":"missing object","command_index":0}]))
    assert result.status=="BLOCKING" and result.cleanup_status=="RESTORED"
    assert result.reference_errors[0].entity_id=="address:source"

@pytest.mark.parametrize("failure,error",[("save_candidate","SNAPSHOT_SAVE_FAILED"),("snapshot_verification","SNAPSHOT_SAVE_FAILED"),("apply","CANDIDATE_APPLY_FAILED"),("validate","VALIDATION_FAILED")])
def test_stage_failures_are_distinct_and_mutation_possible_always_restores(failure,error):
    result=run(FakeTransport(fail=failure))
    assert result.error_state==error and not result.commit_performed
    assert result.cleanup_status==("NOT_REQUIRED" if failure in {"save_candidate","snapshot_verification"} else "RESTORED")
    assert "secret" not in result.model_dump_json()

def test_network_failure_after_partial_application_restores_preexisting_candidate():
    transport=FakeTransport(fail="partial_apply"); result=run(transport)
    assert result.error_state=="CANDIDATE_APPLY_FAILED" and result.cleanup_status=="RESTORED"
    assert result.preexisting_candidate_preserved and transport.state=="running-plus-existing-candidate"

@pytest.mark.parametrize("failure,error,cleanup",[("load_snapshot","RESTORE_FAILED","RESTORE_FAILED"),("verification","RESTORE_UNVERIFIED","RESTORE_UNVERIFIED")])
def test_restore_failure_overrides_validation_result(failure,error,cleanup):
    result=run(FakeTransport(fail=failure))
    assert result.status=="BLOCKING" and result.error_state==error and result.cleanup_status==cleanup

@pytest.mark.parametrize("mode,candidate",[(TargetManagementMode.PANORAMA,command().text),(TargetManagementMode.LOCAL_FIREWALL,"set rulebase nat rules n source any")])
def test_unsafe_scope_blocked_before_connection(mode,candidate):
    transport=FakeTransport(); result=validate_in_lab(candidate+"\n",[command(candidate)],mode,transport)
    assert result.status=="BLOCKING" and transport.calls==[]

def test_version_mismatch_does_not_mutate():
    transport=FakeTransport(version="12.1.0"); result=run(transport)
    assert result.status=="VERSION_MISMATCH" and result.error_state=="VERSION_MISMATCH" and transport.calls==["version"]

@pytest.mark.parametrize("payload",["commit","<commit-all/>","commit-and-push","push config","deploy now"])
def test_commit_and_deployment_shapes_are_denied(payload):
    with pytest.raises(ValueError): assert_safe_request(PanLabOperation.VALIDATE_FULL,payload)

def test_only_enumerated_operations_are_accepted():
    for operation in PanLabOperation: assert_safe_request(operation,"<safe/>")
    with pytest.raises((ValueError,TypeError)): assert_safe_request("ARBITRARY","")

def test_snapshot_name_is_sanitized_and_collision_resistant():
    now=datetime(2026,9,18,tzinfo=timezone.utc); first=snapshot_name(now); second=snapshot_name(now)
    assert first!=second and first.startswith("convert-in-validation-20260918T000000Z-") and first.endswith(".xml")
    assert all(char.isalnum() or char in ".-" for char in first)

def test_result_rejects_commit_or_success_without_verified_restore():
    data=dict(status="PASS",started_at="2026-01-01T00:00:00Z",duration_ms=1,candidate_hash="0"*64)
    with pytest.raises(ValueError): PanLabValidationResult(**data,commit_performed=True)
    with pytest.raises(ValueError): PanLabValidationResult(**data)

def test_endpoint_requires_both_opt_ins_and_remains_blocked(monkeypatch,tmp_path):
    monkeypatch.setattr(settings,"workspace_dir",tmp_path); project="00000000-0000-0000-0000-000000000001"; root=tmp_path/project
    root.mkdir(); (root/"normalized.json").write_text('{"vendor":"cisco_asa"}',encoding="utf-8")
    client=TestClient(app); response=client.post(f"/api/projects/{project}/migration/pan-lab-validation")
    assert response.status_code in {404,409}