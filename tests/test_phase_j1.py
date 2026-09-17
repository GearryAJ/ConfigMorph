import io,json,zipfile
from pathlib import Path
import pytest
from app.core.documentation import DOCUMENTATION_REFERENCES,validate_documentation_registry
from app.core.models import Vendor
from app.core.migration import MigrationMappings,MigrationPlanner
from app.core.parsing import parse_config
from app.core.renderers import PaloAltoRenderer
from app.core.review import build_review,export_package,validate_migration
from app.core.versions import detect_version,resolve_context,version_profile

@pytest.mark.parametrize("text,vendor,version,family",[
    ("ASA Version 9.20(2)\n",Vendor.ASA,"9.20(2)","9.20"),
    ("#config-version=FG100F-7.4.12-FW-build1234-240101:opmode=0:vdom=0\n",Vendor.FORTIGATE,"7.4.12","7.4"),
    ('<config version="11.1.4"><devices/></config>',Vendor.PALO_ALTO,"11.1.4","11.1"),
])
def test_documented_version_detection(text,vendor,version,family):
    result=detect_version(text,vendor); assert (result.detected_version,result.detected_family,result.status)==(version,family,"EXACT")

def test_unknown_unsupported_and_override_are_conservative():
    assert detect_version("config firewall policy",Vendor.FORTIGATE).status=="UNKNOWN"
    assert version_profile(Vendor.FORTIGATE,"8.0") is None
    context=resolve_context("#config-version=FG100F-7.4.12-FW-build1-1:opmode=0:vdom=0",Vendor.FORTIGATE,"7.6")
    assert context.override and context.override_timestamp and context.detected_version=="7.4.12"

def test_documentation_registry_official_and_complete():
    assert len(DOCUMENTATION_REFERENCES)==8 and not validate_documentation_registry()
    assert all(str(x.official_url).startswith("https://") for x in DOCUMENTATION_REFERENCES.values())

def _versioned(vendor,source,target="11.1"):
    return resolve_context("",vendor,source),resolve_context("",Vendor.PALO_ALTO,target)

@pytest.mark.parametrize("vendor,family",[(Vendor.ASA,"9.20"),(Vendor.ASA,"9.22"),(Vendor.ASA,"9.24"),(Vendor.FORTIGATE,"7.4"),(Vendor.FORTIGATE,"7.6")])
def test_version_profiles_downgrade_incomplete_end_to_end_evidence(vendor,family):
    cfg=parse_config("hostname x\n" if vendor==Vendor.ASA else "config firewall address\n edit A\n set subnet 192.0.2.1 255.255.255.255\n next\nend",vendor)
    source,target=_versioned(vendor,family); plan=MigrationPlanner().plan(cfg,MigrationMappings(),source,target)
    assert all(x.status not in {"EXACT","SUPPORTED"} for x in plan.compatibility)

@pytest.mark.parametrize("family",["11.1","12.1"])
def test_panos_renderer_requires_verified_entity_syntax(family):
    cfg=parse_config("config firewall address\n edit A\n set subnet 192.0.2.1 255.255.255.255\n next\nend",Vendor.FORTIGATE)
    source,target=_versioned(Vendor.FORTIGATE,"7.4",family); plan=MigrationPlanner().plan(cfg,MigrationMappings(),source,target)
    lines,report=PaloAltoRenderer().render(plan,version_profile(Vendor.PALO_ALTO,family)); assert not lines and report.version_validation_result=="WARNING"

def test_unknown_target_blocks_validation_and_export_contains_provenance():
    cfg=parse_config("config firewall address\n edit A\n set subnet 192.0.2.1 255.255.255.255\n next\nend",Vendor.FORTIGATE)
    source=resolve_context("",Vendor.FORTIGATE,"7.4"); plan=MigrationPlanner().plan(cfg,MigrationMappings(),source,None)
    lines,report=PaloAltoRenderer().render(plan); review=build_review(cfg,plan,[]); validation=validate_migration(cfg,plan,review,lines)
    assert validation.stages["VERSION"]=="BLOCKING"
    package=export_package("",report.model_dump(mode="json"),review,validation,MigrationMappings())
    with zipfile.ZipFile(io.BytesIO(package)) as archive:
        exported=json.loads(archive.read("review-report.json")); assert exported["source_version"]["selected_family"]=="7.4" and "documentation_refs" in exported

def test_fixture_provenance_is_valid():
    root=Path("tests/fixtures/migration/fortigate_to_pan")
    for case in root.iterdir():
        if case.is_dir():
            data=json.loads((case/"references.json").read_text()); assert data["source_profile"]=="fortios-7.4" and data["target_profile"]=="panos-11.1"