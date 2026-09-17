import ipaddress
import shlex
from app.core.models import (Address, FirewallConfig, Interface, NatRule, ParseIssue,
    Provenance, SecurityRule, Service, Severity, StaticRoute, UnparsedConstruct, Vendor, Zone)
from app.core.parsing.base import DetectionResult


class FortiGateParser:
    vendor = Vendor.FORTIGATE
    known = {"system interface", "system zone", "firewall address", "firewall addrgrp", "firewall service custom", "firewall service group", "firewall policy", "firewall vip", "router static"}
    consumed = {
        "system interface": {"alias","description","ip","status","vdom","type","interface","vlanid","role"}, "system zone": {"interface","description"},
        "firewall address": {"subnet","fqdn","start-ip","end-ip","comment"}, "firewall addrgrp": {"member","comment"},
        "firewall service custom": {"tcp-portrange","udp-portrange","protocol","comment"}, "firewall service group": {"member","comment"},
        "firewall policy": {"name","srcintf","dstintf","srcaddr","dstaddr","service","action","status","nat","ippool","poolname","comments"},
        "firewall vip": {"extip","mappedip","extintf","portforward","extport","mappedport","protocol","comment"},
        "router static": {"dst","gateway","device","distance","priority","status"},
    }
    def detect(self, text: str) -> DetectionResult:
        hits = [x for x in ("config firewall policy", "set srcintf", "set dstintf", "config firewall address") if x in text.lower()]
        return DetectionResult(self.vendor, min(1, len(hits) / 3), hits)
    def validate_input(self, text: str):
        return [] if text.strip() else [ParseIssue(severity=Severity.ERROR, vendor=self.vendor, message="Configuration is empty")]
    def parse(self, text: str) -> FirewallConfig:
        lines = text.splitlines(); cfg = FirewallConfig(metadata={"source_vendor": self.vendor}); cfg.warnings.extend(self.validate_input(text)); stack=[]; item=None
        for number, raw in enumerate(lines, 1):
            line = raw.strip()
            if not line or line.startswith("#"): continue
            try: parts = shlex.split(line, comments=False)
            except ValueError: self._unparsed(cfg, number, self._section(stack), line, "Malformed quoting", Severity.ERROR); continue
            command = parts[0]
            if command == "config":
                stack.append(" ".join(parts[1:])); continue
            if command == "edit":
                if item: self._emit(cfg, self._section(stack), item, truncated=True)
                item = {"name": parts[1] if len(parts)>1 else f"unnamed-{number}", "values": {}, "line": number, "raw": []}; continue
            if command in {"set","unset"}:
                if item is None: self._unparsed(cfg, number, self._section(stack), line, "Setting outside edit block"); continue
                if len(parts)<2: self._unparsed(cfg, number, self._section(stack), line, "Malformed setting"); continue
                item["values"][parts[1]] = parts[2:] if command == "set" else []; item["raw"].append(line); continue
            if command == "next":
                if item: self._emit(cfg, self._section(stack), item); item=None
                else: self._unparsed(cfg, number, self._section(stack), line, "Unexpected next")
                continue
            if command == "end":
                if item: self._emit(cfg, self._section(stack), item, truncated=True); item=None
                if stack: stack.pop()
                else: self._unparsed(cfg, number, None, line, "Unexpected end")
                continue
            self._unparsed(cfg, number, self._section(stack), line, "Unsupported FortiGate command")
        if item: self._emit(cfg, self._section(stack), item, truncated=True)
        for section in stack: self._unparsed(cfg, len(lines) or 1, section, f"config {section}", "Missing end block")
        self._references(cfg); return cfg.finalize_metrics(len(lines))
    def _section(self, stack): return stack[-1] if stack else None
    def _emit(self, cfg, section, item, truncated=False):
        name=item["name"]; values=item["values"]; line=item["line"]; one=lambda key,default=None: values.get(key,[default])[0]; p=Provenance(source_vendor=self.vendor,source_line=line,source_section=section)
        if section not in self.known:
            self._unparsed(cfg,line,section,"\n".join(item["raw"]),"Unsupported configuration block"); return
        extensions={k:v for k,v in values.items() if k not in self.consumed[section]}
        if truncated: extensions["truncated_block"]=True; cfg.warnings.append(ParseIssue(severity=Severity.WARNING,vendor=self.vendor,section=section,line=line,message="Edit block missing next"))
        try:
            if section == "system interface":
                ips=[]
                if "ip" in values: ips=[str(ipaddress.ip_network(f"{values['ip'][0]}/{values['ip'][1]}",strict=False))]
                cfg.interfaces.append(Interface(id=name,name=name,description=one("description") or one("alias"),ipv4=ips,enabled=one("status","up") not in {"down","disable"},vlan=int(one("vlanid")) if one("vlanid") else None,parent=one("interface"),type=one("type","physical"),provenance=p,vendor_extensions=extensions))
            elif section == "system zone": cfg.zones.append(Zone(id=name,name=name,interfaces=values.get("interface",[]),description=one("description"),provenance=p,vendor_extensions=extensions))
            elif section == "firewall address":
                kind="fqdn" if "fqdn" in values else "range" if "start-ip" in values else "network"; value=one("fqdn") or (f"{one('start-ip')}-{one('end-ip')}" if "start-ip" in values else self._network(values.get("subnet",[])))
                cfg.addresses.append(Address(id=name,name=name,type=kind,value=value,description=one("comment"),provenance=p,vendor_extensions=extensions))
            elif section == "firewall addrgrp": cfg.address_groups.append(Address(id=name,name=name,type="group",members=values.get("member",[]),description=one("comment"),provenance=p,vendor_extensions=extensions))
            elif section == "firewall service custom":
                proto="tcp" if "tcp-portrange" in values else "udp" if "udp-portrange" in values else one("protocol","ip").lower(); cfg.services.append(Service(id=name,name=name,protocol=proto,destination_ports=values.get("tcp-portrange",values.get("udp-portrange",[])),description=one("comment"),provenance=p,vendor_extensions=extensions))
            elif section == "firewall service group": cfg.service_groups.append(Service(id=name,name=name,protocol="group",members=values.get("member",[]),description=one("comment"),provenance=p,vendor_extensions=extensions))
            elif section == "firewall policy":
                rule=SecurityRule(id=name,name=one("name",name),position=len(cfg.security_policies)+1,source_zones=values.get("srcintf",[]),destination_zones=values.get("dstintf",[]),sources=values.get("srcaddr",["any"]),destinations=values.get("dstaddr",["any"]),services=values.get("service",["any"]),action=one("action","deny"),enabled=one("status","enable")=="enable",description=one("comments"),provenance=p,vendor_extensions=extensions); cfg.security_policies.append(rule)
                if one("nat","disable")=="enable": cfg.nat_policies.append(NatRule(id=f"policy-nat-{name}",name=f"Policy NAT {rule.name}",type="dynamic_pat",original_source=rule.sources,translated_source=values.get("poolname",["interface"]),status="PARTIAL",provenance=p,vendor_extensions={"policy":name,"ippool":one("ippool","disable")}))
            elif section == "firewall vip": cfg.nat_policies.append(NatRule(id=f"vip-{name}",name=name,type="destination_nat",original_destination=values.get("extip",[]),translated_destination=values.get("mappedip",[]),status="PARTIAL",provenance=p,vendor_extensions={**extensions,**{k:v for k,v in values.items() if k in {"extintf","portforward","extport","mappedport","protocol"}}}))
            elif section == "router static": cfg.static_routes.append(StaticRoute(id=f"route-{name}",name=f"route {name}",destination=self._network(values.get("dst",["0.0.0.0","0.0.0.0"])),next_hop=one("gateway","0.0.0.0"),interface=one("device"),distance=int(one("distance",10)),metric=int(one("priority",0)),enabled=one("status","enable")=="enable",provenance=p,vendor_extensions=extensions))
        except (ValueError, IndexError) as exc: self._unparsed(cfg,line,section,"\n".join(item["raw"]),f"Invalid value: {exc}",Severity.ERROR)
        for key in extensions: self._unparsed(cfg,line,section,f"set {key} {' '.join(values[key])}","Unsupported field preserved",Severity.INFO)
    def _network(self, values):
        if len(values)<2: raise ValueError("missing address mask")
        return str(ipaddress.ip_network(f"{values[0]}/{values[1]}",strict=False))
    def _unparsed(self,cfg,line,section,raw,reason,severity=Severity.WARNING):
        cfg.unparsed_constructs.append(UnparsedConstruct(vendor=self.vendor,section=section,line_number=line,raw_text=raw,reason=reason,severity=severity)); cfg.warnings.append(ParseIssue(severity=severity,vendor=self.vendor,section=section,line=line,message=reason,raw_text=raw))
    def _references(self,cfg):
        addresses={"all","any"}|{x.name for x in cfg.addresses+cfg.address_groups}; services={"ALL","any"}|{x.name for x in cfg.services+cfg.service_groups}
        for rule in cfg.security_policies:
            for ref in rule.sources+rule.destinations:
                if ref not in addresses: cfg.warnings.append(ParseIssue(severity=Severity.WARNING,vendor=self.vendor,object=rule.name,message=f"Unresolved address reference: {ref}"))
            for ref in rule.services:
                if ref not in services: cfg.warnings.append(ParseIssue(severity=Severity.WARNING,vendor=self.vendor,object=rule.name,message=f"Unresolved service reference: {ref}"))