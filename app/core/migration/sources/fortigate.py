import ipaddress
from app.core.models import FirewallConfig, Vendor
from .base import MigrationSourceAdapter


class FortiGateSourceAdapter(MigrationSourceAdapter):
    vendor = Vendor.FORTIGATE

    def adapt(self, config: FirewallConfig) -> FirewallConfig:
        zones = {zone.name: zone for zone in config.zones}
        membership = {interface: zone.name for zone in config.zones for interface in zone.interfaces}
        for interface in config.interfaces:
            interface.zone = membership.get(interface.name, interface.name)
        for rule in config.security_policies:
            rule.ingress_interfaces = [i for context in rule.source_zones for i in (zones[context].interfaces if context in zones else [context])]
            rule.egress_interfaces = [i for context in rule.destination_zones for i in (zones[context].interfaces if context in zones else [context])]
            rule.vendor_extensions["topology"] = {
                "status": "RESOLVED",
                "evidence": [f"FortiGate source context: {', '.join(rule.source_zones)}", f"FortiGate destination context: {', '.join(rule.destination_zones)}"],
            }
        policies = {str(rule.id): rule for rule in config.security_policies}
        for nat in config.nat_policies:
            policy = policies.get(str(nat.vendor_extensions.get("policy")))
            if nat.type == "destination_nat" and not policy:
                matches=[rule for rule in config.security_policies if nat.name in rule.destinations]
                policy=matches[0] if len(matches)==1 else None
                if len(matches)>1: nat.vendor_extensions["manual_review"]="VIP is referenced by multiple firewall policies; route outcome is ambiguous."
            if policy:
                nat.source_zones = list(policy.source_zones)
                nat.destination_zones = list(policy.destination_zones)
                nat.position = policy.position
                nat.vendor_extensions["policy"]=str(policy.id)
            if nat.type == "destination_nat" and not nat.destination_zones and len(nat.translated_destination) == 1:
                try:
                    address=ipaddress.ip_address(nat.translated_destination[0]); matches=[i for i in config.interfaces if any(address in ipaddress.ip_network(network,strict=False) for network in i.ipv4)]
                    if len(matches)==1: nat.destination_zones=[matches[0].zone or matches[0].name]
                except ValueError: pass
            if nat.type == "destination_nat" and (len(nat.original_destination)!=1 or len(nat.translated_destination)!=1 or not nat.source_zones or not nat.destination_zones):
                nat.vendor_extensions["manual_review"]="VIP translation or topology is incomplete."
        if config.metadata.get("vdom_present"):
            for entity in config.security_policies+config.nat_policies+config.static_routes: entity.vendor_extensions["manual_review"]="VDOM configuration is not automatically flattened into one PAN-OS vsys."
        if config.metadata.get("sdwan_present"):
            for route in config.static_routes: route.vendor_extensions["manual_review"]="FortiGate SD-WAN routing is not automatically migrated."
        return config
