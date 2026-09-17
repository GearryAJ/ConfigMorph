from datetime import datetime, timezone
from enum import StrEnum
from typing import Any
from pydantic import BaseModel, Field, field_validator
from app.core.models import Vendor

class CompatibilityStatus(StrEnum):
    EXACT="EXACT"; SUPPORTED="SUPPORTED"; PARTIAL="PARTIAL"; MANUAL_REVIEW="MANUAL_REVIEW"; UNSUPPORTED="UNSUPPORTED"

class CompatibilityResult(BaseModel):
    entity_id:str; entity_type:str; source_name:str; status:CompatibilityStatus
    reasons:list[str]=Field(default_factory=list); required_mappings:list[str]=Field(default_factory=list); source_context:str|None=None
    topology:dict[str,Any]=Field(default_factory=dict)

class InterfaceMapping(BaseModel):
    source_interface:str; source_nameif:str|None=None; target_interface:str|None=None; target_zone:str|None=None; suggested_zone:str|None=None; confirmed:bool=False

class MigrationMappings(BaseModel):
    mode:str="vsys"; vsys:str="vsys1"; device_group:str|None=None; virtual_router:str="default"
    interfaces:list[InterfaceMapping]=Field(default_factory=list)
    @field_validator("mode")
    @classmethod
    def valid_mode(cls,v):
        if v not in {"vsys","device_group"}: raise ValueError("mode must be vsys or device_group")
        return v
    @field_validator("vsys","virtual_router")
    @classmethod
    def safe_context(cls,v):
        if not v.strip() or any(x in v for x in "\r\n\t\"'\\"): raise ValueError("invalid target context")
        return v

class NameMapping(BaseModel):
    entity_id:str; source_name:str; target_name:str; reason:str|None=None; collision:bool=False

class PlannedEntity(BaseModel):
    entity_id:str; entity_type:str; target_name:str; data:dict[str,Any]

class MigrationPlan(BaseModel):
    source_vendor:Vendor; target_vendor:Vendor=Vendor.PALO_ALTO; mappings:MigrationMappings
    compatibility:list[CompatibilityResult]; names:list[NameMapping]; generate:list[PlannedEntity]
    blocked:list[str]=Field(default_factory=list); advisories:list[str]=Field(default_factory=list)

class CategoryCounts(BaseModel):
    objects:int=0; services:int=0; interfaces:int=0; zones:int=0; security_policies:int=0; nat_policies:int=0; routes:int=0

class MigrationReport(BaseModel):
    source_vendor:Vendor; target_vendor:Vendor; generated_at:str=Field(default_factory=lambda:datetime.now(timezone.utc).isoformat())
    total_entities:int; exact:int; supported:int; partial:int; manual_review:int; unsupported:int
    categories:CategoryCounts; warnings:list[str]=Field(default_factory=list); errors:list[str]=Field(default_factory=list)
    required_mappings:list[str]=Field(default_factory=list); generated_entities:int=0; skipped_entities:int=0
    compatibility:list[CompatibilityResult]; names:list[NameMapping]

class PanSetCommand(BaseModel):
    path:list[str]; values:list[str]=Field(default_factory=list); entity_id:str; text:str=""

class RenderResult(BaseModel):
    status:str; generated_lines:int; generated_entities:int; skipped_entities:int; manual_review:int; unsupported:int
    candidate_path:str|None=None; report:MigrationReport; candidate:str|None=None