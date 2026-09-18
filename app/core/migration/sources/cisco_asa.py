from app.core.models import FirewallConfig, Vendor
from app.vendors.cisco_asa.topology import AsaTopologyResolver
from .base import MigrationSourceAdapter


class CiscoAsaSourceAdapter(MigrationSourceAdapter):
    vendor = Vendor.ASA

    def adapt(self, config: FirewallConfig) -> FirewallConfig:
        config=AsaTopologyResolver(config).apply()
        config.nat_policies.sort(key=lambda rule:(rule.vendor_extensions.get("section",99),rule.vendor_extensions.get("sequence",rule.position or 0)))
        for position,rule in enumerate(config.nat_policies,1): rule.position=position
        return config
