from datetime import datetime, timezone
from enum import StrEnum
from typing import Any
from pydantic import BaseModel, Field, field_validator, model_validator
from app.core.models import Vendor
from app.core.versions.models import VersionContext

class CompatibilityStatus(StrEnum):
    EXACT="EXACT"; SUPPORTED="SUPPORTED"; PARTIAL="PARTIAL"; MANUAL_REVIEW="MANUAL_REVIEW"; UNSUPPORTED="UNSUPPORTED"

class CompatibilityResult(BaseModel):
    entity_id:str; entity_type:str; source_name:str; status:CompatibilityStatus
    reasons:list[str]=Field(default_factory=list); required_mappings:list[str]=Field(default_factory=list); source_context:str|None=None
    topology:dict[str,Any]=Field(default_factory=dict)
    source_version:str|None=None; target_version:str|None=None; capability_refs:list[str]=Field(default_factory=list); documentation_refs:list[str]=Field(default_factory=list); version_status:str="VERSION_NOT_VERIFIED"

class InterfaceMapping(BaseModel):
    source_interface:str; source_nameif:str|None=None; target_interface:str|None=None; target_zone:str|None=None; suggested_zone:str|None=None; confirmed:bool=False

class TargetManagementMode(StrEnum):
    LOCAL_FIREWALL="LOCAL_FIREWALL"; PANORAMA="PANORAMA"

class RulebaseScope(StrEnum):
    PRE="PRE"; POST="POST"

class MigrationMappings(BaseModel):
    management_mode:TargetManagementMode=TargetManagementMode.LOCAL_FIREWALL
    vsys:str="vsys1"; device_group:str|None=None; rulebase_scope:RulebaseScope|None=None; virtual_router:str="default"
    interfaces:list[InterfaceMapping]=Field(default_factory=list)
    @model_validator(mode="before")
    @classmethod
    def legacy_mode(cls,v):
        if isinstance(v,dict) and "mode" in v and "management_mode" not in v:
            v=dict(v); v["management_mode"]="PANORAMA" if v.pop("mode")=="device_group" else "LOCAL_FIREWALL"
        return v
    @field_validator("vsys","virtual_router","device_group")
    @classmethod
    def safe_context(cls,v):
        if v is not None and (not v.strip() or not __import__("re").fullmatch(r"[A-Za-z0-9._-]+",v)): raise ValueError("invalid target context")
        return v
    @model_validator(mode="after")
    def panorama_context(self):
        if self.management_mode==TargetManagementMode.PANORAMA and not self.device_group: raise ValueError("Panorama requires device_group")
        if self.management_mode==TargetManagementMode.PANORAMA and not self.rulebase_scope: raise ValueError("Panorama requires rulebase_scope")
        return self

class NameMapping(BaseModel):
    entity_id:str; source_name:str; target_name:str; reason:str|None=None; collision:bool=False

class PlannedEntity(BaseModel):
    entity_id:str; entity_type:str; target_name:str; data:dict[str,Any]

class MigrationPlan(BaseModel):
    source_vendor:Vendor; target_vendor:Vendor=Vendor.PALO_ALTO; mappings:MigrationMappings
    compatibility:list[CompatibilityResult]; names:list[NameMapping]; generate:list[PlannedEntity]
    blocked:list[str]=Field(default_factory=list); advisories:list[str]=Field(default_factory=list)
    source_version:VersionContext|None=None; target_version:VersionContext|None=None

class CategoryCounts(BaseModel):
    objects:int=0; services:int=0; interfaces:int=0; zones:int=0; security_policies:int=0; nat_policies:int=0; routes:int=0

class MigrationReport(BaseModel):
    source_vendor:Vendor; target_vendor:Vendor; generated_at:str=Field(default_factory=lambda:datetime.now(timezone.utc).isoformat())
    total_entities:int; exact:int; supported:int; partial:int; manual_review:int; unsupported:int
    categories:CategoryCounts; warnings:list[str]=Field(default_factory=list); errors:list[str]=Field(default_factory=list)
    required_mappings:list[str]=Field(default_factory=list); generated_entities:int=0; skipped_entities:int=0
    compatibility:list[CompatibilityResult]; names:list[NameMapping]
    source_version:VersionContext|None=None; target_version:VersionContext|None=None; documentation_refs:list[str]=Field(default_factory=list); version_validation_result:str="BLOCKING"

class PanSetCommand(BaseModel):
    operation:str="SET"; path:list[str]; values:list[str]=Field(default_factory=list); entity_id:str; text:str=""
    target_profile:str; capability_id:str; documentation_refs:list[str]
    management_context:MigrationMappings

class RenderResult(BaseModel):
    status:str; generated_lines:int; generated_entities:int; skipped_entities:int; manual_review:int; unsupported:int
    candidate_path:str|None=None; report:MigrationReport; candidate:str|None=None