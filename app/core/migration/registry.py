from dataclasses import dataclass
from app.core.models import Vendor
from .sources import CiscoAsaSourceAdapter, FortiGateSourceAdapter, MigrationSourceAdapter


@dataclass(frozen=True)
class MigrationPair:
    source_adapter: type[MigrationSourceAdapter]
    target_renderer: str
    features: frozenset[str]
    documentation: str


SUPPORTED_MIGRATION_PAIRS = {
    (Vendor.ASA, Vendor.PALO_ALTO): MigrationPair(CiscoAsaSourceAdapter, "PaloAltoRenderer", frozenset({"policy", "nat", "route"}), "asa-to-pan"),
    (Vendor.FORTIGATE, Vendor.PALO_ALTO): MigrationPair(FortiGateSourceAdapter, "PaloAltoRenderer", frozenset({"policy", "nat", "vip", "route"}), "fortigate-to-pan"),
}


def migration_pair(source: Vendor | str, target: Vendor | str = Vendor.PALO_ALTO) -> MigrationPair:
    try:
        pair = SUPPORTED_MIGRATION_PAIRS[(Vendor(source), Vendor(target))]
    except (ValueError, KeyError) as exc:
        raise ValueError(f"Unsupported migration pair: {source} to {target}") from exc
    return pair