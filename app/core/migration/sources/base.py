from abc import ABC, abstractmethod

from app.core.models import FirewallConfig, Vendor


class MigrationSourceAdapter(ABC):
    vendor: Vendor

    @abstractmethod
    def adapt(self, config: FirewallConfig) -> FirewallConfig:
        """Return normalized migration semantics without reading source syntax."""
