import re
from .models import MigrationMappings, NameMapping

def normalize_names(entities):
    used=set(); out=[]
    for entity in entities:
        base=re.sub(r"[^\w.-]+","_",entity.name,flags=re.UNICODE).strip("_.-") or "unnamed"
        base=base[:63]; target=base; number=2
        while target.casefold() in used:
            suffix=f"_{number}"; target=base[:63-len(suffix)]+suffix; number+=1
        collision=target!=base; used.add(target.casefold())
        reason="Normalized unsupported punctuation" if base!=entity.name else None
        if collision: reason="Name collision resolved deterministically"
        out.append(NameMapping(entity_id=entity.id,source_name=entity.name,target_name=target,reason=reason,collision=collision))
    return out

def default_mappings(cfg):
    from .models import InterfaceMapping
    memberships={interface:zone.name for zone in cfg.zones for interface in zone.interfaces}
    return MigrationMappings(interfaces=[InterfaceMapping(source_interface=x.name,source_nameif=x.zone or memberships.get(x.name) or x.name,suggested_zone=x.zone or memberships.get(x.name) or x.name) for x in cfg.interfaces])

def confirmed_maps(mappings:MigrationMappings):
    interfaces={x.source_interface:x for x in mappings.interfaces if x.confirmed}
    interfaces.update({x.source_nameif:x for x in mappings.interfaces if x.confirmed and x.source_nameif})
    zones={x.source_nameif:x.target_zone for x in mappings.interfaces if x.confirmed and x.source_nameif and x.target_zone}
    return interfaces,zones