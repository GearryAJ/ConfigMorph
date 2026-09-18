from collections import Counter
from app.core.documentation import validate_documentation_registry
import argparse
from app.core.versions import EMITTED_CAPABILITIES,PROFILES,emitted_capability_fully_evidenced
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

def release_coverage():
    target=PROFILES["panos-11.1"]
    pairs=[PROFILES[f"asa-{version}"] for version in ("9.20","9.22","9.24")]+[PROFILES[f"fortios-{version}"] for version in ("7.4","7.6")]
    states=[(source,name,emitted_capability_fully_evidenced(source,target,name)) for source in pairs for name in EMITTED_CAPABILITIES]
    missing_docs=[f"{source.id}:{name}" for source,name,complete in states if not complete and (not source.capabilities[name].documentation_refs or not target.capabilities[name].documentation_refs)]
    missing_tests=[f"{source.id}:{name}" for source,name,complete in states if not complete and (not source.tested or not target.tested or source.capabilities[name].status!=CapabilityStatus.DOCUMENTED_IMPLEMENTED_TESTED or target.capabilities[name].status!=CapabilityStatus.DOCUMENTED_IMPLEMENTED_TESTED)]
    return {"emitted_capabilities_total":len(states),"emitted_capabilities_fully_evidenced":sum(complete for _,_,complete in states),"emitted_capabilities_missing_docs":len(missing_docs),"emitted_capabilities_missing_tests":len(missing_tests),"missing_docs":missing_docs,"missing_tests":missing_tests}

if __name__=="__main__":
    parser=argparse.ArgumentParser(); parser.add_argument("--release",action="store_true"); args=parser.parse_args()
    for key,value in (release_coverage() if args.release else coverage()).items(): print(f"{key}: {value}")