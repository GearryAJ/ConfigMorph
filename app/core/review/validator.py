import ipaddress
from collections import Counter
from app.core.migration.validation import validate_candidate
from .models import ValidationFinding,ValidationReport,ValidationSeverity as S

def validate_migration(cfg,plan,review,lines):
    findings=[]
    def add(stage,severity,code,message,entity=None): findings.append(ValidationFinding(stage=stage,severity=severity,code=code,message=message,entity_id=entity))
    entities=[x for xs in (cfg.interfaces,cfg.zones,cfg.addresses,cfg.address_groups,cfg.services,cfg.service_groups,cfg.security_policies,cfg.nat_policies,cfg.static_routes,cfg.vpn_objects) for x in xs]
    ids=[x.id for x in entities]
    if len(ids)!=len(set(ids)): add("STRUCTURAL",S.BLOCKING,"DUPLICATE_ID","Entity IDs are not globally unique.")
    for x in cfg.addresses:
        if x.type in {"host","network"}:
            try: ipaddress.ip_network(x.value,strict=False)
            except (ValueError,TypeError): add("STRUCTURAL",S.BLOCKING,"INVALID_NETWORK",f"Invalid address value: {x.name}",x.id)
    refs={x.name for x in cfg.addresses+cfg.address_groups+cfg.services+cfg.service_groups}|{"any","application-default","service-http","service-https","interface"}
    for x in cfg.security_policies:
        for ref in x.sources+x.destinations+x.services:
            if ref not in refs: add("REFERENCE",S.BLOCKING,"MISSING_SOURCE_REFERENCE",f"Unresolved source reference: {ref}",x.id)
    compatibility={x.entity_id:x for x in plan.compatibility}
    if set(ids)!=set(compatibility): add("MIGRATION",S.BLOCKING,"SILENT_OMISSION","Compatibility accounting omits or adds entities.")
    generated=review.summary.generated; manual=review.summary.manual_review; unsupported=review.summary.unsupported
    accounted=generated+manual+unsupported
    # PARTIAL/EXACT/SUPPORTED entities that emit nothing are an error; mapping-only entities remain explicit manual review.
    if accounted!=review.summary.total: add("MIGRATION",S.BLOCKING,"ACCOUNTING_MISMATCH",f"Generated {generated} + manual review {manual} + unsupported {unsupported} != source {review.summary.total}.")
    for x in plan.compatibility:
        if x.required_mappings: add("MIGRATION",S.WARNING,"MAPPING_REQUIRED",f"Unconfirmed mappings: {', '.join(x.required_mappings)}",x.entity_id)
    for error in validate_candidate(lines): add("CANDIDATE",S.BLOCKING,"INVALID_COMMAND",error)
    target_names=[x.target_name.lower() for x in plan.generate]
    for name,count in Counter(target_names).items():
        if count>1: add("CANDIDATE",S.BLOCKING,"TARGET_COLLISION",f"Duplicate target name: {name}")
    created={x.target_name for x in plan.generate if x.entity_type in {"address","address_group","service","service_group"}}
    builtins={"any","application-default","service-http","service-https","interface"}
    for x in plan.generate:
        if x.entity_type in {"address_group","service_group"}:
            for ref in x.data.get("members",[]):
                if ref not in created|builtins: add("CANDIDATE",S.BLOCKING,"MISSING_TARGET_REFERENCE",f"Missing target reference: {ref}",x.entity_id)
        if x.entity_type in {"security_policy","nat_policy"}:
            for key in ("source","destination","service","translated_source"):
                values=x.data.get(key,[]); values=[values] if isinstance(values,str) else values
                for ref in values:
                    if ref not in created|builtins and not _ip(ref): add("CANDIDATE",S.BLOCKING,"MISSING_TARGET_REFERENCE",f"Missing target reference: {ref}",x.entity_id)
    for item in review.items:
        for finding in item.analysis_findings:
            if finding["severity"]=="WARNING": add("REVIEW",S.WARNING,finding["type"],finding["description"],item.id)
    stages={stage:_stage(findings,stage) for stage in ("STRUCTURAL","REFERENCE","MIGRATION","CANDIDATE","REVIEW")}
    status=S.BLOCKING if S.BLOCKING in stages.values() else S.WARNING if S.WARNING in stages.values() else S.PASS
    return ValidationReport(status=status,findings=findings,stages=stages)

def _ip(value):
    try: ipaddress.ip_address(value); return True
    except (ValueError,TypeError): return False
def _stage(findings,stage):
    levels=[x.severity for x in findings if x.stage==stage]
    return S.BLOCKING if S.BLOCKING in levels else S.WARNING if S.WARNING in levels else S.PASS