from collections import Counter
from .models import CategoryCounts, CompatibilityStatus, MigrationReport

def build_report(plan, generated_ids=(), errors=()):
    counts=Counter(x.status for x in plan.compatibility); types=Counter(x.entity_type for x in plan.compatibility); generated=set(generated_ids)
    required=sorted({value for x in plan.compatibility for value in x.required_mappings})
    renderable={x.entity_id for x in plan.generate}; emitted=generated & renderable
    return MigrationReport(source_vendor=plan.source_vendor,target_vendor=plan.target_vendor,total_entities=len(plan.compatibility),exact=counts[CompatibilityStatus.EXACT],supported=counts[CompatibilityStatus.SUPPORTED],partial=counts[CompatibilityStatus.PARTIAL],manual_review=counts[CompatibilityStatus.MANUAL_REVIEW],unsupported=counts[CompatibilityStatus.UNSUPPORTED],categories=CategoryCounts(objects=types["address"]+types["address_group"],services=types["service"]+types["service_group"],interfaces=types["interface"],zones=types["zone"],security_policies=types["security_policy"],nat_policies=types["nat_policy"],routes=types["route"]),warnings=plan.advisories,errors=list(errors)+plan.blocked,required_mappings=required,generated_entities=len(emitted),skipped_entities=len(plan.compatibility)-len(emitted),compatibility=plan.compatibility,names=plan.names)