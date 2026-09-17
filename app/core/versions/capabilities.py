from .models import CapabilityStatus

VERIFIED={CapabilityStatus.DOCUMENTED_IMPLEMENTED_TESTED}
def capability_verified(profile,name): return bool(profile and name in profile.capabilities and profile.capabilities[name].status in VERIFIED and profile.capabilities[name].documentation_refs)

def evidence_state(source_profile,target_profile,name,command=None):
    source=source_profile.capabilities.get(name) if source_profile else None
    target=target_profile.capabilities.get(name) if target_profile else None
    documented=bool(target and target.documentation_refs)
    verified=bool(source and target and source.status in VERIFIED and target.status in VERIFIED)
    return EvidenceState(source_semantic_documented=bool(source and source.documentation_refs),target_semantic_documented=documented,target_cli_documented=documented,renderer_syntax_verified=verified,ordering_verified=name!="security_policy",tests_verified=bool(source_profile and target_profile and source_profile.tested and target_profile.tested and (command is None or command.tests)),version_verified=bool(source_profile and target_profile and source_profile.version_family and target_profile.version_family and (command is None or command.target_profile==target_profile.id)))

from .models import EvidenceState