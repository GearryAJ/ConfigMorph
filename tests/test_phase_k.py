from app.core.documentation import DOCUMENTATION_REFERENCES,validate_documentation_registry
from app.core.migration.models import CompatibilityStatus
from app.core.versions import PROFILES,evidence_state
from app.tools.doc_coverage import coverage

def test_registry_and_coverage_have_no_orphans():
    assert len(DOCUMENTATION_REFERENCES)>=18
    assert not validate_documentation_registry()
    assert coverage()["capabilities_total"]==sum(len(profile.capabilities) for profile in PROFILES.values())

def test_no_optimistic_supported_capability():
    for source in PROFILES.values():
        if source.vendor.value=="paloalto": continue
        for target in (PROFILES["panos-11.1"],PROFILES["panos-12.1"]):
            for name in source.capabilities.keys() & target.capabilities.keys():
                state=evidence_state(source,target,name)
                if not state.complete:
                    assert not (source.capabilities[name].status.value==CompatibilityStatus.SUPPORTED or target.capabilities[name].status.value==CompatibilityStatus.EXACT)

def test_panos_12_1_does_not_inherit_11_1_evidence():
    assert not PROFILES["panos-12.1"].documentation_refs
    assert all(not capability.documentation_refs for capability in PROFILES["panos-12.1"].capabilities.values())

def test_panos_12_1_change_authorities_are_registered_without_restoration():
    expected={
        "PANOS-12.1-CONFIGURE-CLI-HIERARCHY",
        "PANOS-12.1-SET-COMMANDS-INTRODUCED",
        "PANOS-12.1-SET-COMMANDS-REMOVED",
    }
    assert expected <= DOCUMENTATION_REFERENCES.keys()
    assert all(not capability.documentation_refs for capability in PROFILES["panos-12.1"].capabilities.values())