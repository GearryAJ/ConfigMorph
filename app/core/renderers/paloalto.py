import re
from app.core.migration.models import PanSetCommand
from app.core.migration.report import build_report

def quote(value:str):
    if any(x in value for x in "\r\n\0"): raise ValueError("unsafe PAN-OS value")
    return '"'+value.replace('\\','\\\\').replace('"','\\"')+'"' if re.search(r"\s|[\"\\]",value) else value

class PaloAltoRenderer:
    def render(self,plan,target_profile=None):
        if target_profile is None and plan.target_version:
            from app.core.versions import version_profile
            target_profile=version_profile(plan.target_vendor,plan.target_version.selected_family)
        if target_profile is None:
            self.commands=[]
            return [],build_report(plan,(),["Target PAN-OS version profile is required."])
        commands=[]; generated=set(); errors=[]
        prefix=["set",("device-group" if plan.mappings.mode=="device_group" else "vsys"),plan.mappings.device_group or plan.mappings.vsys]
        def emit(entity,*parts,context=True): commands.append(PanSetCommand(path=(prefix if context else ["set"])+list(parts),entity_id=entity.entity_id)); generated.add(entity.entity_id)
        for e in plan.generate:
            try:
                d=e.data; n=e.target_name
                if e.entity_type=="address": emit(e,"address",n,"ip-range" if d["type"]=="range" else "fqdn" if d["type"]=="fqdn" else "ip-netmask",d["value"])
                elif e.entity_type in {"address_group","service_group"}:
                    kind="address-group" if e.entity_type=="address_group" else "service-group"
                    for member in d["members"]: emit(e,kind,n,"static",member)
                elif e.entity_type=="service":
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
                    for field in ("from","to","source","destination"):
                        for value in d[field]: emit(e,"rulebase","nat","rules",n,field,value)
                    emit(e,"rulebase","nat","rules",n,"service",d["service"])
                    if d["type"]=="dynamic_pat": emit(e,"rulebase","nat","rules",n,"source-translation","dynamic-ip-and-port","interface-address","interface")
                    elif d["type"]=="destination_nat":
                        emit(e,"rulebase","nat","rules",n,"destination-translation","translated-address",d["translated_destination"][0])
                        if d.get("translated_service"): emit(e,"rulebase","nat","rules",n,"destination-translation","translated-port",d["translated_service"])
                    else:
                        for value in d["translated_source"]: emit(e,"rulebase","nat","rules",n,"source-translation","static-ip","translated-address",value)
                elif e.entity_type=="route":
                    root=("network","virtual-router",d["virtual_router"],"routing-table","ip","static-route",n)
                    emit(e,*root,"destination",d["destination"],context=False); emit(e,*root,"nexthop","ip-address",d["next_hop"],context=False)
                    if d["interface"]: emit(e,*root,"interface",d["interface"],context=False)
                    if d["metric"] is not None: emit(e,*root,"metric",str(d["metric"]),context=False)
            except (KeyError,ValueError) as exc: errors.append(f"{e.entity_id}: {exc}")
        lines=[" ".join(quote(x) for x in c.path+c.values) for c in commands]
        for command,line in zip(commands,lines): command.text=line
        self.commands=commands
        report=build_report(plan,generated,errors)
        return lines,report