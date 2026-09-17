from dataclasses import dataclass
from typing import Protocol
from app.core.models import FirewallConfig, ParseIssue, Vendor


@dataclass(frozen=True)
class DetectionResult:
    vendor: Vendor
    confidence: float
    evidence: list[str]


class FirewallParser(Protocol):
    vendor: Vendor
    def detect(self, text: str) -> DetectionResult: ...
    def parse(self, text: str) -> FirewallConfig: ...
    def validate_input(self, text: str) -> list[ParseIssue]: ...