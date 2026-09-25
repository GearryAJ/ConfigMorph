import re
from collections.abc import Iterable

from app.core.models import Interface

from .catalog import HardwareCatalog, load_hardware_catalog
from .models import (
    AlertSeverity,
    CapacitySummary,
    HardwareAlert,
    HardwareMigrationPlan,
    InterfaceMappingSuggestion,
    MappingStatus,
    ReferenceStatus,
    ReviewAction,
)


PHYSICAL_INTERFACE = re.compile(r"^ethernet(?P<slot>\d+)/(?P<port>\d+)(?P<unit>\.\d+)?$", re.I)
LOGICAL_INTERFACE = re.compile(r"^(?:ae|loopback|tunnel|vlan)\d+(?:\.\d+)?$", re.I)


class HardwareMigrationAnalyzer:
    def __init__(self, catalog: HardwareCatalog | None = None):
        self.catalog = catalog or load_hardware_catalog()

    def analyze(
        self,
        interfaces: Iterable[Interface],
        source_model: str,
        target_model: str,
        source_version: str | None = None,
        target_version: str | None = None,
    ) -> HardwareMigrationPlan:
        source = self.catalog.find(source_model)
        target = self.catalog.find(target_model)
        interface_list = list(interfaces)
        source_capacity = source.total_interface if isinstance(source.total_interface, int) else None
        target_capacity = target.total_interface if isinstance(target.total_interface, int) else None
        alerts: list[HardwareAlert] = []
        documentation_refs = list(
            dict.fromkeys(
                source.documentation_refs
                + target.documentation_refs
                + ["PANOS-11.1-INTERFACE-NAMING"]
            )
        )

        physical_groups: dict[str, list[tuple[Interface, re.Match[str]]]] = {}
        logical: list[Interface] = []
        unknown: list[Interface] = []
        for interface in interface_list:
            match = PHYSICAL_INTERFACE.fullmatch(interface.name)
            if match:
                base = f"ethernet{int(match.group('slot'))}/{int(match.group('port'))}"
                physical_groups.setdefault(base, []).append((interface, match))
            elif LOGICAL_INTERFACE.fullmatch(interface.name):
                logical.append(interface)
            else:
                unknown.append(interface)

        mappings: list[InterfaceMappingSuggestion] = []
        target_interfaces = (
            [f"ethernet1/{port}" for port in range(1, target_capacity + 1)]
            if target_capacity is not None
            else []
        )
        used_targets: set[str] = set()
        base_targets: dict[str, str | None] = {}

        if target_capacity is None:
            alerts.append(
                self._alert(
                    "TARGET_CAPACITY_NOT_FIXED",
                    AlertSeverity.BLOCKING,
                    f"{target.model} has modular interface capacity. Select installed network cards before assigning ports.",
                    "REVIEW_TARGET_HARDWARE",
                    "Review target hardware",
                    list(physical_groups),
                    target.documentation_refs,
                )
            )
        else:
            for source_base, members in physical_groups.items():
                match = members[0][1]
                preferred = f"ethernet1/{int(match.group('port'))}"
                if int(match.group("slot")) == 1 and preferred in target_interfaces and preferred not in used_targets:
                    base_targets[source_base] = preferred
                    used_targets.add(preferred)
                    continue
                available = next((name for name in target_interfaces if name not in used_targets), None)
                base_targets[source_base] = available
                if available:
                    used_targets.add(available)

        remapped: list[str] = []
        unmapped: list[str] = []
        for source_base, members in physical_groups.items():
            target_base = base_targets.get(source_base)
            for interface, match in members:
                suffix = match.group("unit") or ""
                target_name = f"{target_base}{suffix}" if target_base else None
                if target_name is None:
                    status = MappingStatus.UNMAPPED
                    reason = "No target physical port remains."
                    unmapped.append(interface.name)
                elif source_base.casefold() == target_base.casefold():
                    status = MappingStatus.PRESERVED
                    reason = "The same numbered target port is within capacity."
                else:
                    status = MappingStatus.REMAPPED
                    reason = "The source port is outside the available target numbering or already assigned."
                    remapped.append(interface.name)
                mappings.append(
                    InterfaceMappingSuggestion(
                        source_interface=interface.name,
                        target_interface=target_name,
                        status=status,
                        consumes_physical_port=not bool(suffix),
                        reason=reason,
                    )
                )

        for interface in logical:
            mappings.append(
                InterfaceMappingSuggestion(
                    source_interface=interface.name,
                    target_interface=interface.name,
                    status=MappingStatus.LOGICAL_PRESERVED,
                    consumes_physical_port=False,
                    reason="Logical interfaces do not consume a physical data-plane port.",
                )
            )
        for interface in unknown:
            mappings.append(
                InterfaceMappingSuggestion(
                    source_interface=interface.name,
                    status=MappingStatus.MANUAL_REVIEW,
                    consumes_physical_port=False,
                    reason="The interface name is not a verified PAN-OS physical or logical pattern.",
                )
            )

        configured_ports = len(physical_groups)
        if source_capacity is None:
            alerts.append(
                self._alert(
                    "SOURCE_CAPACITY_NOT_FIXED",
                    AlertSeverity.WARNING,
                    f"{source.model} has modular interface capacity. The source chassis inventory must be reviewed.",
                    "REVIEW_SOURCE_HARDWARE",
                    "Review source hardware",
                    list(physical_groups),
                    source.documentation_refs,
                )
            )
        elif configured_ports > source_capacity or any(
            int(group[0][1].group("port")) > source_capacity for group in physical_groups.values()
        ):
            alerts.append(
                self._alert(
                    "SOURCE_INTERFACE_OUT_OF_RANGE",
                    AlertSeverity.WARNING,
                    f"The configuration references ports outside the recorded {source.model} capacity of {source_capacity}.",
                    "REVIEW_SOURCE_INTERFACES",
                    "Review source interfaces",
                    [item.name for item in interface_list],
                    source.documentation_refs,
                )
            )
        if unmapped:
            alerts.append(
                self._alert(
                    "TARGET_CAPACITY_SHORTFALL",
                    AlertSeverity.BLOCKING,
                    f"{target.model} cannot accept {len(unmapped)} configured interface mapping(s) within its recorded capacity.",
                    "REVIEW_UNMAPPED_INTERFACES",
                    "Review unmapped interfaces",
                    unmapped,
                    target.documentation_refs,
                )
            )
        if remapped:
            alerts.append(
                self._alert(
                    "INTERFACE_RENUMBERING_REQUIRED",
                    AlertSeverity.WARNING,
                    f"{len(remapped)} interface mapping(s) require a different target port number.",
                    "REVIEW_INTERFACE_MAPPING",
                    "Review interface mapping",
                    remapped,
                    documentation_refs,
                )
            )
        if unknown:
            alerts.append(
                self._alert(
                    "INTERFACE_TYPE_NOT_VERIFIED",
                    AlertSeverity.WARNING,
                    f"{len(unknown)} interface name(s) require manual classification.",
                    "REVIEW_INTERFACE_MAPPING",
                    "Review interface mapping",
                    [item.name for item in unknown],
                    documentation_refs,
                )
            )
        if source.model != target.model:
            alerts.append(
                self._alert(
                    "MEDIA_REVIEW_REQUIRED",
                    AlertSeverity.WARNING,
                    "Port media and speed compatibility cannot be proven from configuration alone. Compare optics, cabling, breakout mode, and link speed before deployment.",
                    "REVIEW_PORT_MEDIA",
                    "Review port media",
                    [item.source_interface for item in mappings if item.consumes_physical_port],
                    documentation_refs,
                )
            )

        version_status = self._version_status(target.model, target_version)
        if version_status != "VERIFIED":
            message = (
                f"PAN-OS {target_version or 'target version'} is below the first supported release recorded for {target.model}."
                if version_status == "UNSUPPORTED"
                else f"PAN-OS compatibility for {target.model} is not verified at the selected patch release."
            )
            alerts.append(
                self._alert(
                    "TARGET_VERSION_NOT_VERIFIED",
                    AlertSeverity.BLOCKING if version_status == "UNSUPPORTED" else AlertSeverity.WARNING,
                    message,
                    "REVIEW_TARGET_VERSION",
                    "Review target version",
                    [],
                    target.documentation_refs,
                )
            )
        if source.reference_status is ReferenceStatus.LOCAL_REFERENCE_ONLY or target.reference_status is ReferenceStatus.LOCAL_REFERENCE_ONLY:
            alerts.append(
                self._alert(
                    "HARDWARE_REFERENCE_NOT_VERIFIED",
                    AlertSeverity.WARNING,
                    "At least one selected model has only local catalog metadata. Verify its current vendor datasheet before deployment.",
                    "REVIEW_HARDWARE_REFERENCE",
                    "Review hardware reference",
                    [],
                    documentation_refs,
                )
            )

        assigned = len(used_targets)
        status = "BLOCKING" if any(alert.severity is AlertSeverity.BLOCKING for alert in alerts) else "REVIEW_REQUIRED"
        return HardwareMigrationPlan(
            source=source,
            target=target,
            source_capacity=CapacitySummary(
                configured_physical_ports=configured_ports,
                catalog_capacity=source_capacity,
                assigned_physical_ports=configured_ports,
                available_physical_ports=(max(source_capacity - configured_ports, 0) if source_capacity is not None else None),
                interface_types=source.interface_types,
            ),
            target_capacity=CapacitySummary(
                configured_physical_ports=configured_ports,
                catalog_capacity=target_capacity,
                assigned_physical_ports=assigned,
                available_physical_ports=(max(target_capacity - assigned, 0) if target_capacity is not None else None),
                interface_types=target.interface_types,
            ),
            target_interfaces=target_interfaces,
            mappings=sorted(mappings, key=lambda item: item.source_interface.casefold()),
            alerts=alerts,
            status=status,
            source_version=source_version,
            target_version=target_version,
            version_status=version_status,
            documentation_refs=documentation_refs,
        )

    @staticmethod
    def _alert(
        code: str,
        severity: AlertSeverity,
        message: str,
        action_code: str,
        action_label: str,
        interfaces: list[str],
        refs: list[str],
    ) -> HardwareAlert:
        return HardwareAlert(
            code=code,
            severity=severity,
            message=message,
            action=ReviewAction(code=action_code, label=action_label, interface_names=interfaces),
            documentation_refs=refs,
        )

    @staticmethod
    def _version_status(model: str, selected: str | None) -> str:
        minimums = {
            **{f"PA-{number}": "12.2.2" for number in (5510, 5520, 5530)},
            **{f"PA-{number}": "12.1.2" for number in (5540, 5550, 5560, 5570, 5580)},
        }
        minimum = minimums.get(model)
        if minimum is None:
            return "VERSION_NOT_VERIFIED"
        if selected is None:
            return "VERSION_NOT_VERIFIED"
        selected_parts = tuple(int(part) for part in selected.split(".") if part.isdigit())
        minimum_parts = tuple(int(part) for part in minimum.split("."))
        if len(selected_parts) < len(minimum_parts):
            return (
                "UNSUPPORTED"
                if selected_parts[:2] < minimum_parts[:2]
                else "VERSION_NOT_VERIFIED"
            )
        padded = selected_parts + (0,) * (len(minimum_parts) - len(selected_parts))
        if padded < minimum_parts:
            return "UNSUPPORTED"
        return "VERIFIED"
