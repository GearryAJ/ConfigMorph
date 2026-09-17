from app.core.models import FirewallConfig, Vendor
from app.vendors.cisco_asa.topology import AsaTopologyResolver
from .base import MigrationSourceAdapter


class CiscoAsaSourceAdapter(MigrationSourceAdapter):
    vendor = Vendor.ASA

    def adapt(self, config: FirewallConfig) -> FirewallConfig:
        return AsaTopologyResolver(config).apply()
