from .models import CompatibilityResult, CompatibilityStatus

def result(entity,kind,status,*reasons,required=(),topology=None):
    context=None
    if entity.provenance: context=f"{entity.provenance.source_section or 'source'} line {entity.provenance.source_line or '?'}"
    return CompatibilityResult(entity_id=entity.id,entity_type=kind,source_name=entity.name,status=status,reasons=list(reasons),required_mappings=list(required),source_context=context,topology=topology or {})