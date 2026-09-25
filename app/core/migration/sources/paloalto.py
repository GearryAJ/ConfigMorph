from app.core.models import FirewallConfig, Vendor

from .base import MigrationSourceAdapter


class PaloAltoSourceAdapter(MigrationSourceAdapter):
    vendor = Vendor.PALO_ALTO

    def adapt(self, config: FirewallConfig) -> FirewallConfig:
        memberships = {
            interface: zone.name for zone in config.zones for interface in zone.interfaces
        }
        for interface in config.interfaces:
            interface.zone = memberships.get(interface.name, interface.zone)
        return config
