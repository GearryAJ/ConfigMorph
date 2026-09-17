from .models import CapabilityStatus

VERIFIED={CapabilityStatus.DOCUMENTED_IMPLEMENTED_TESTED}
def capability_verified(profile,name): return bool(profile and name in profile.capabilities and profile.capabilities[name].status in VERIFIED and profile.capabilities[name].documentation_refs)