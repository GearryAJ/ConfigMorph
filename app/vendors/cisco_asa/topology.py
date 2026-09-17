import ipaddress
from enum import StrEnum
from pydantic import BaseModel, Field

class TopologyStatus(StrEnum):
    RESOLVED="RESOLVED"; MULTIPLE="MULTIPLE"; AMBIGUOUS="AMBIGUOUS"; UNRESOLVED="UNRESOLVED"

class TopologyResolution(BaseModel):
    status:TopologyStatus
    interfaces:list[str]=Field(default_factory=list)
    zones:list[str]=Field(default_factory=list)
    evidence:list[str]=Field(default_factory=list)
    reason:str|None=None

class AsaTopologyResolver:
    """Deterministic configured-state resolver. No DNS or live routing."""
    def __init__(self,cfg):
        self.cfg=cfg; self.objects={x.name:x for x in cfg.addresses+cfg.address_groups}; self.groups={x.name:x for x in cfg.address_groups}; self.cache={}
        self.interfaces={x.name:x for x in cfg.interfaces}; self.by_context={x.zone:x for x in cfg.interfaces if x.zone}
        self.routes=[]
        for interface in cfg.interfaces:
            for value in interface.ipv4:
                try:self.routes.append((ipaddress.ip_network(value,strict=False),0,interface.zone or interface.name,"connected"))
                except ValueError:pass
        for route in cfg.static_routes:
            try:self.routes.append((ipaddress.ip_network(route.destination,strict=False),route.distance if route.distance is not None else 1,route.interface,"static route"))
            except ValueError:pass

    def _members(self,name,stack=()):
        if name in self.cache:return self.cache[name]
        if name in stack:return None
        obj=self.objects.get(name)
        if not obj:return [name]
        if obj.type!="group":return [obj.value] if obj.value else None
        out=[]
        for member in obj.members:
            values=self._members(member,stack+(name,))
            if values is None:return None
            out.extend(values)
        self.cache[name]=out; return out

    def _lookup(self,value):
        try: target=ipaddress.ip_network(value,strict=False)
        except (ValueError,TypeError):return TopologyResolution(status=TopologyStatus.UNRESOLVED,reason="Destination is not a deterministic IP network; DNS is disabled.")
        matches=[x for x in self.routes if x[0].version==target.version and (target.subnet_of(x[0]) or target.overlaps(x[0]))]
        if not matches:return TopologyResolution(status=TopologyStatus.UNRESOLVED,reason=f"No configured route covers {target}.")
        prefix=max(x[0].prefixlen for x in matches); best=[x for x in matches if x[0].prefixlen==prefix]; metric=min(x[1] for x in best); best=[x for x in best if x[1]==metric]
        contexts=sorted({x[2] for x in best}); interfaces=sorted({self.by_context.get(x).name if x in self.by_context else x for x in contexts})
        if len(contexts)!=1:return TopologyResolution(status=TopologyStatus.AMBIGUOUS,interfaces=interfaces,zones=contexts,evidence=[f"{target} matches {x[0]} via {x[2]}" for x in best],reason="Equal-prefix routes select multiple contexts.")
        route=best[0]; return TopologyResolution(status=TopologyStatus.RESOLVED,interfaces=interfaces,zones=contexts,evidence=[f"{target} matches {route[3]} {route[0]} on {route[2]}."])

    def resolve(self,destinations):
        if not destinations or any(x.lower() in {"any","any4","any6"} for x in destinations):return TopologyResolution(status=TopologyStatus.AMBIGUOUS,reason="Any destination is not narrowed to a target zone.")
        results=[]
        for name in destinations:
            values=self._members(name)
            if values is None:return TopologyResolution(status=TopologyStatus.UNRESOLVED,reason=f"Address group {name} is cyclic or unresolved.")
            results.extend(self._lookup(x) for x in values)
        if any(x.status!=TopologyStatus.RESOLVED for x in results):
            first=next(x for x in results if x.status!=TopologyStatus.RESOLVED); return first
        zones=sorted({z for x in results for z in x.zones}); interfaces=sorted({i for x in results for i in x.interfaces}); evidence=[e for x in results for e in x.evidence]
        return TopologyResolution(status=TopologyStatus.RESOLVED if len(zones)==1 else TopologyStatus.MULTIPLE,interfaces=interfaces,zones=zones,evidence=evidence,reason=None if len(zones)==1 else "Destination members span multiple contexts.")

    def apply(self):
        for rule in self.cfg.security_policies:
            attachment=rule.vendor_extensions.get("attachment",{}); direction=attachment.get("direction")
            if direction=="in": rule.ingress_interfaces=[attachment["interface"]]; rule.source_zones=[attachment["interface"]]
            resolution=self.resolve(rule.destinations); rule.vendor_extensions["topology"]=resolution.model_dump(mode="json")
            if direction=="in" and resolution.status==TopologyStatus.RESOLVED: rule.egress_interfaces=resolution.interfaces; rule.destination_zones=resolution.zones
        return self.cfg