from enum import StrEnum

from pydantic import BaseModel, Field


class ReferenceStatus(StrEnum):
    OFFICIAL = "OFFICIAL"
    LOCAL_REFERENCE_ONLY = "LOCAL_REFERENCE_ONLY"


class HardwareModel(BaseModel):
    series: str
    model: str
    segment_form_factor: str
    firewall_appid_throughput: str | None = None
    threat_prevention: str | None = None
    max_sessions: str | None = None
    total_interface: int | str
    interface_types: str
    notes: str | None = None
    documentation_refs: list[str] = Field(default_factory=list)
    reference_status: ReferenceStatus = ReferenceStatus.LOCAL_REFERENCE_ONLY


class MappingStatus(StrEnum):
    PRESERVED = "PRESERVED"
    REMAPPED = "REMAPPED"
    LOGICAL_PRESERVED = "LOGICAL_PRESERVED"
    MANUAL_REVIEW = "MANUAL_REVIEW"
    UNMAPPED = "UNMAPPED"


class AlertSeverity(StrEnum):
    INFO = "INFO"
    WARNING = "WARNING"
    BLOCKING = "BLOCKING"


class ReviewAction(BaseModel):
    code: str
    label: str
    interface_names: list[str] = Field(default_factory=list)


class HardwareAlert(BaseModel):
    code: str
    severity: AlertSeverity
    message: str
    action: ReviewAction
    documentation_refs: list[str] = Field(default_factory=list)


class InterfaceMappingSuggestion(BaseModel):
    source_interface: str
    target_interface: str | None = None
    status: MappingStatus
    consumes_physical_port: bool
    reason: str


class CapacitySummary(BaseModel):
    configured_physical_ports: int
    catalog_capacity: int | None
    assigned_physical_ports: int
    available_physical_ports: int | None
    interface_types: str


class HardwareMigrationPlan(BaseModel):
    source: HardwareModel
    target: HardwareModel
    source_capacity: CapacitySummary
    target_capacity: CapacitySummary
    target_interfaces: list[str] = Field(default_factory=list)
    mappings: list[InterfaceMappingSuggestion] = Field(default_factory=list)
    alerts: list[HardwareAlert] = Field(default_factory=list)
    status: str
    source_version: str | None = None
    target_version: str | None = None
    version_status: str = "VERSION_NOT_VERIFIED"
    documentation_refs: list[str] = Field(default_factory=list)
