import ipaddress
from defusedxml import ElementTree as ET
from defusedxml.common import DefusedXmlException
from app.core.models import (Address, FirewallConfig, Interface, NatRule, ParseIssue,
    Provenance, SecurityRule, Service, Severity, StaticRoute, UnparsedConstruct, Vendor, Zone)
from app.core.parsing.base import DetectionResult


class PaloAltoParser:
    vendor = Vendor.PALO_ALTO
    def detect(self, text: str) -> DetectionResult:
        hits = [x for x in ("<config", "<devices", "<vsys") if x in text.lower()]
        return DetectionResult(self.vendor, len(hits) / 3, hits)
    def validate_input(self, text: str):
        return [] if text.strip() else [ParseIssue(severity=Severity.ERROR,vendor=self.vendor,message="Configuration is empty")]
    def parse(self, text: str) -> FirewallConfig:
        cfg=FirewallConfig(metadata={"source_vendor":self.vendor}); cfg.warnings.extend(self.validate_input(text))
        if not text.strip(): return cfg.finalize_metrics(0)
        try: root=ET.fromstring(text)
        except (ET.ParseError,DefusedXmlException,ValueError) as exc:
            self._unparsed(cfg,None,"xml",text[:1000],f"Unsafe or invalid XML: {exc}",Severity.ERROR); return cfg.finalize_metrics(0)
        p=Provenance(source_vendor=self.vendor)
        for e in root.findall(".//address/entry"):
            child=next((e.find(x) for x in ("ip-netmask","ip-range","fqdn") if e.find(x) is not None),None)
            if child is None: self._xml_unparsed(cfg,e,"address","No supported address value"); continue
            value=child.text or ""
            try:
                if child.tag=="ip-netmask": value=str(ipaddress.ip_network(value,strict=False)) if "/" in value else str(ipaddress.ip_address(value))
            except ValueError: self._xml_unparsed(cfg,e,"address","Invalid IP/CIDR",Severity.ERROR); continue
            cfg.addresses.append(Address(id=e.attrib.get("name","unnamed"),name=e.attrib.get("name","unnamed"),type={"ip-netmask":"network" if "/" in value else "host","ip-range":"range","fqdn":"fqdn"}[child.tag],value=value,description=e.findtext("description"),provenance=p,vendor_extensions=self._extensions(e,{child.tag,"description","tag"})))
        for e in root.findall(".//address-group/entry"):
            cfg.address_groups.append(Address(id=e.attrib.get("name","unnamed"),name=e.attrib.get("name","unnamed"),type="group",members=self._members(e,"./static/member"),description=e.findtext("description"),provenance=p,vendor_extensions=self._extensions(e,{"static","description","tag"})))
        for e in root.findall(".//service/entry"):
            proto="tcp" if e.find("./protocol/tcp") is not None else "udp" if e.find("./protocol/udp") is not None else None
            if not proto: self._xml_unparsed(cfg,e,"service","Unknown service protocol"); continue
            ports=(e.findtext(f"./protocol/{proto}/port") or "").split(",")
            try: cfg.services.append(Service(id=e.attrib["name"],name=e.attrib["name"],protocol=proto,destination_ports=[x for x in ports if x],description=e.findtext("description"),provenance=p,vendor_extensions=self._extensions(e,{"protocol","description","tag"})))
            except ValueError as exc: self._xml_unparsed(cfg,e,"service",str(exc),Severity.ERROR)
        for e in root.findall(".//service-group/entry"):
            cfg.service_groups.append(Service(id=e.attrib["name"],name=e.attrib["name"],protocol="group",members=self._members(e,"./members/member"),provenance=p,vendor_extensions=self._extensions(e,{"members","tag"})))
        self._interfaces(root,cfg,p); self._zones(root,cfg,p); self._policies(root,cfg,p); self._nat(root,cfg,p); self._routes(root,cfg,p)
        known={"devices","entry","vsys","address","address-group","service","service-group","network","interface","ethernet","layer3","ip","zone","virtual-router","routing-table","ip","static-route","rulebase","security","nat","rules"}
        for child in root:
            if child.tag not in known: self._xml_unparsed(cfg,child,"config","Unsupported top-level XML section",Severity.INFO)
        return cfg.finalize_metrics(sum(1 for _ in root.iter()))
    def _interfaces(self,root,cfg,p):
        for e in root.findall(".//network/interface/ethernet/entry"):
            ips=[x.attrib.get("name","") for x in e.findall("./layer3/ip/entry")]; cfg.interfaces.append(Interface(id=e.attrib["name"],name=e.attrib["name"],ipv4=ips,enabled=True,provenance=p,vendor_extensions=self._extensions(e,{"layer3","comment"})))
    def _zones(self,root,cfg,p):
        for e in root.findall(".//zone/entry"):
            cfg.zones.append(Zone(id=e.attrib["name"],name=e.attrib["name"],interfaces=self._members(e,"./network/layer3/member"),provenance=p,vendor_extensions=self._extensions(e,{"network","enable-user-identification"})))
    def _policies(self,root,cfg,p):
        for pos,e in enumerate(root.findall(".//rulebase/security/rules/entry"),1):
            cfg.security_policies.append(SecurityRule(id=e.attrib["name"],name=e.attrib["name"],position=pos,source_zones=self._members(e,"./from/member"),destination_zones=self._members(e,"./to/member"),sources=self._members(e,"./source/member") or ["any"],destinations=self._members(e,"./destination/member") or ["any"],services=self._members(e,"./service/member") or ["any"],action=e.findtext("action","unknown"),enabled=e.findtext("disabled","no")!="yes",description=e.findtext("description"),provenance=p,vendor_extensions=self._extensions(e,{"from","to","source","destination","service","action","disabled","description","tag","log-start","log-end"})))
    def _nat(self,root,cfg,p):
        for e in root.findall(".//rulebase/nat/rules/entry"):
            src=self._members(e,"./source/member"); dst=self._members(e,"./destination/member"); translated=[]; kind="source_nat"
            dynamic=e.find("./source-translation/dynamic-ip-and-port")
            if dynamic is not None: translated=self._members(dynamic,"./translated-address/member") or ["interface"]; kind="dynamic_pat"
            destination=e.find("./destination-translation")
            translated_dst=[destination.findtext("translated-address","")] if destination is not None else []
            if destination is not None: kind="destination_nat" if dynamic is None else "source_destination_nat"
            cfg.nat_policies.append(NatRule(id=e.attrib["name"],name=e.attrib["name"],type=kind,original_source=src,translated_source=translated,original_destination=dst,translated_destination=[x for x in translated_dst if x],status="PARTIAL",provenance=p,vendor_extensions=self._extensions(e,{"from","to","source","destination","service","source-translation","destination-translation","disabled","description"})))
    def _routes(self,root,cfg,p):
        for vr in root.findall(".//virtual-router/entry"):
            for e in vr.findall("./routing-table/ip/static-route/entry"):
                cfg.static_routes.append(StaticRoute(id=f"{vr.attrib['name']}:{e.attrib['name']}",name=e.attrib["name"],destination=e.findtext("destination","0.0.0.0/0"),next_hop=e.findtext("./nexthop/ip-address","0.0.0.0"),interface=e.findtext("interface"),metric=int(e.findtext("metric","10")),enabled=e.findtext("disabled","no")!="yes",provenance=p,vendor_extensions={"virtual_router":vr.attrib["name"],**self._extensions(e,{"destination","nexthop","interface","metric","admin-dist","disabled"})}))
    def _members(self,e,path): return [x.text or "" for x in e.findall(path)]
    def _extensions(self,e,known): return {x.tag:ET.tostring(x,encoding="unicode") for x in e if x.tag not in known}
    def _xml_unparsed(self,cfg,e,section,reason,severity=Severity.WARNING): self._unparsed(cfg,None,section,ET.tostring(e,encoding="unicode"),reason,severity)
    def _unparsed(self,cfg,line,section,raw,reason,severity=Severity.WARNING):
        cfg.unparsed_constructs.append(UnparsedConstruct(vendor=self.vendor,section=section,line_number=line,raw_text=raw,reason=reason,severity=severity)); cfg.warnings.append(ParseIssue(severity=severity,vendor=self.vendor,section=section,line=line,message=reason,raw_text=raw))