from collections import Counter
from app.core.documentation import validate_documentation_registry
from app.core.versions import PROFILES
from app.core.versions.models import CapabilityStatus

def coverage():
    capabilities=[capability for profile in PROFILES.values() for capability in profile.capabilities.values()]
    counts=Counter(capability.status for capability in capabilities)
    return {
        "capabilities_total":len(capabilities),
        "fully_evidenced":counts[CapabilityStatus.DOCUMENTED_IMPLEMENTED_TESTED],
        "missing_tests":counts[CapabilityStatus.DOCUMENTED_IMPLEMENTED_UNTESTED],
        "missing_documentation":sum(not capability.documentation_refs for capability in capabilities),
        "registry_errors":validate_documentation_registry(),
    }

if __name__=="__main__":
    for key,value in coverage().items(): print(f"{key}: {value}")