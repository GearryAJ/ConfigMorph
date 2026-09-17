import re
from app.core.migration.models import PanSetCommand,TargetManagementMode
from app.core.migration.report import build_report

_NAME=re.compile(r"[A-Za-z0-9._-]+")
_VALUE=re.compile(r"[A-Za-z0-9._:/,-]+")

def quote(value:str):
    if not _VALUE.fullmatch(value): raise ValueError(f"unsafe PAN-OS token: {value!r}")
    return value

class PaloAltoRenderer:
    def render(self,plan,target_profile=None):
        if target_profile is None and plan.target_version:
            from app.core.versions import version_profile
            target_profile=version_profile(plan.target_vendor,plan.target_version.selected_family)
        if target_profile is None:
            self.commands=[]
            return [],build_report(plan,(),["Target PAN-OS version profile is required."])
        if plan.mappings.management_mode==TargetManagementMode.PANORAMA:
            self.commands=[]
            return [],build_report(plan,(),["Panorama candidate generation requires separately implemented device-group and pre/post-rulebase paths."])
        commands=[]; generated=set(); errors=[]
        compatibility={x.entity_id:x for x in plan.compatibility}
        def emit(entity,*parts):
            evidence=compatibility[entity.entity_id]
            if not evidence.documentation_refs: raise ValueError("command documentation provenance required")
            if not _NAME.fullmatch(entity.target_name): raise ValueError(f"unsafe PAN-OS name: {entity.target_name!r}")
            command=PanSetCommand(path=["set",*parts],entity_id=entity.entity_id,target_profile=target_profile.id,capability_id=evidence.capability_refs[-1],documentation_refs=evidence.documentation_refs,management_context=plan.mappings)
            command.text=" ".join(quote(token) for token in command.path+command.values)
            commands.append(command)
            generated.add(entity.entity_id)
        for e in plan.generate:
            try:
                d=e.data; n=e.target_name
                if e.entity_type=="address": emit(e,"address",n,"ip-range" if d["type"]=="range" else "fqdn" if d["type"]=="fqdn" else "ip-netmask",d["value"])
                elif e.entity_type in {"address_group","service_group"}:
                    kind="address-group" if e.entity_type=="address_group" else "service-group"
                    for member in d["members"]: emit(e,kind,n,"static",member)
                elif e.entity_type=="service":
                    if d["protocol"] not in {"tcp","udp"}: raise ValueError("unsupported service protocol")
                    for ports in d["ports"]: emit(e,"service",n,"protocol",d["protocol"],"port",ports)
                elif e.entity_type=="security_policy":
                    for field in ("from","to","source","destination","service"):
                        for value in d[field]: emit(e,"rulebase","security","rules",n,field,value)
                    emit(e,"rulebase","security","rules",n,"action",d["action"])
                    if not d["enabled"]: emit(e,"rulebase","security","rules",n,"disabled","yes")
                    if d["description"]: emit(e,"rulebase","security","rules",n,"description",d["description"])
                    if d["log_start"]: emit(e,"rulebase","security","rules",n,"log-start","yes")
                    if d["log_end"]: emit(e,"rulebase","security","rules",n,"log-end","yes")
                elif e.entity_type=="nat_policy":
                    raise ValueError("NAT subtype target semantics are not verified")
                elif e.entity_type=="route":
                    if target_profile.version_family!="11.1": raise ValueError("legacy virtual-router route path is limited to PAN-OS 11.1")
                    root=("network","virtual-router",d["virtual_router"],"routing-table","ip","static-route",n)
                    emit(e,*root,"destination",d["destination"]); emit(e,*root,"nexthop","ip-address",d["next_hop"])
                    if d["interface"]: emit(e,*root,"interface",d["interface"])
                    if d["metric"] is not None: emit(e,*root,"metric",str(d["metric"]))
            except (KeyError,ValueError) as exc: errors.append(f"{e.entity_id}: {exc}")
        self.commands=commands
        report=build_report(plan,generated,errors)
        return [x.text for x in commands],report