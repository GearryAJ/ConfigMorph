from .models import CapabilityStatus

VERIFIED={CapabilityStatus.DOCUMENTED_IMPLEMENTED_TESTED}
def capability_verified(profile,name): return bool(profile and name in profile.capabilities and profile.capabilities[name].status in VERIFIED and profile.capabilities[name].documentation_refs)

def evidence_state(source_profile,target_profile,name,command=None):
    source=source_profile.capabilities.get(name) if source_profile else None
    target=target_profile.capabilities.get(name) if target_profile else None
    documented=bool(target and target.documentation_refs)
    verified=bool(source and target and source.status in VERIFIED and target.status in VERIFIED)
    nat=name in {"static_source_nat","dynamic_ip_and_port","interface_address_pat","destination_static_nat","destination_port_translation","identity_nat","twice_nat","ip_pool_snat","central_nat"}
    return EvidenceState(source_semantic_documented=bool(source and source.documentation_refs),target_match_semantics_documented=bool(target and target.target_match_semantics_documented) if nat else documented,target_translation_semantics_documented=bool(target and target.target_translation_semantics_documented) if nat else documented,target_cli_documented=documented,route_lookup_semantics_documented=bool(target and target.route_lookup_semantics_documented) if nat else True,renderer_syntax_verified=verified,ordering_verified=not nat,placement_verified=not nat,mapping_verified=not nat,tests_verified=bool(source_profile and target_profile and source_profile.tested and target_profile.tested and (command is None or command.tests)),version_verified=bool(source_profile and target_profile and source_profile.version_family and target_profile.version_family and (command is None or command.target_profile==target_profile.id)))

from .models import EvidenceState