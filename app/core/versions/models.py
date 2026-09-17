from enum import StrEnum
from pydantic import BaseModel,Field
from app.core.models import Vendor

class VersionConfidence(StrEnum): HIGH="HIGH"; MEDIUM="MEDIUM"; LOW="LOW"; NONE="NONE"
class VersionDetectionStatus(StrEnum): EXACT="EXACT"; FAMILY_ONLY="FAMILY_ONLY"; UNKNOWN="UNKNOWN"; USER_SELECTED="USER_SELECTED"; USER_OVERRIDE="USER_OVERRIDE"
class CapabilityStatus(StrEnum):
    DOCUMENTED_IMPLEMENTED_TESTED="DOCUMENTED_IMPLEMENTED_TESTED"
    DOCUMENTED_IMPLEMENTED_UNTESTED="DOCUMENTED_IMPLEMENTED_UNTESTED"
    DOCUMENTED_NOT_IMPLEMENTED="DOCUMENTED_NOT_IMPLEMENTED"
    IMPLEMENTED_NOT_DOCUMENTATION_VERIFIED="IMPLEMENTED_NOT_DOCUMENTATION_VERIFIED"
    VERSION_NOT_VERIFIED="VERSION_NOT_VERIFIED"
    NOT_APPLICABLE="NOT_APPLICABLE"
    UNKNOWN="UNKNOWN"

class VendorVersion(BaseModel): vendor:Vendor; os_name:str; value:str
class VersionFamily(BaseModel): vendor:Vendor; os_name:str; value:str
class Capability(BaseModel): status:CapabilityStatus; documentation_refs:list[str]=Field(default_factory=list); syntax_variant:str|None=None; limitation:str|None=None
class VersionProfile(BaseModel):
    id:str; vendor:Vendor; os_name:str; version_family:str; documentation_refs:list[str]=Field(default_factory=list)
    capabilities:dict[str,Capability]=Field(default_factory=dict); syntax_variants:dict[str,str]=Field(default_factory=dict); known_limitations:list[str]=Field(default_factory=list); tested:bool=False
class VersionDetectionResult(BaseModel):
    vendor:Vendor; os_name:str; detected_version:str|None=None; detected_family:str|None=None
    status:VersionDetectionStatus=VersionDetectionStatus.UNKNOWN; method:str="none"; confidence:VersionConfidence=VersionConfidence.NONE
class VersionContext(BaseModel):
    vendor:Vendor; os_name:str; detected_version:str|None=None; detected_family:str|None=None
    selected_version:str|None=None; selected_family:str|None=None; detection_method:str="none"
    confidence:VersionConfidence=VersionConfidence.NONE; override:bool=False; override_timestamp:str|None=None