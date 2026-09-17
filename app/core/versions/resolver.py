import re
from datetime import datetime,timezone
from app.core.models import Vendor
from .models import VersionConfidence,VersionContext,VersionDetectionResult,VersionDetectionStatus

OS_NAMES={Vendor.ASA:"Cisco ASA",Vendor.FORTIGATE:"FortiOS",Vendor.PALO_ALTO:"PAN-OS"}
PATTERNS={
    Vendor.ASA: re.compile(r"^ASA Version\s+(\d+\.\d+(?:\([^)]+\))?)\s*$",re.M|re.I),
    Vendor.FORTIGATE: re.compile(r"^#config-version=FG[^-\s]*-(\d+\.\d+\.\d+)-",re.M|re.I),
    Vendor.PALO_ALTO: re.compile(r"<config\b[^>]*\bversion=[\"'](\d+\.\d+(?:\.\d+)?)[\"']",re.I),
}

def version_family(value:str|None):
    match=re.match(r"^(\d+\.\d+)",value or "")
    return match.group(1) if match else None

def detect_version(text:str,vendor:Vendor)->VersionDetectionResult:
    match=PATTERNS[vendor].search(text)
    if not match: return VersionDetectionResult(vendor=vendor,os_name=OS_NAMES[vendor])
    value=match.group(1); return VersionDetectionResult(vendor=vendor,os_name=OS_NAMES[vendor],detected_version=value,detected_family=version_family(value),status=VersionDetectionStatus.EXACT,method="documented configuration metadata",confidence=VersionConfidence.HIGH)

def resolve_context(text:str,vendor:Vendor,selected:str|None=None)->VersionContext:
    detected=detect_version(text,vendor); family=version_family(selected); override=bool(selected and detected.detected_family and family!=detected.detected_family)
    return VersionContext(vendor=vendor,os_name=detected.os_name,detected_version=detected.detected_version,detected_family=detected.detected_family,selected_version=selected,selected_family=family,detection_method=VersionDetectionStatus.USER_OVERRIDE if override else VersionDetectionStatus.USER_SELECTED if selected else detected.status,confidence=detected.confidence,override=override,override_timestamp=datetime.now(timezone.utc).isoformat() if override else None)