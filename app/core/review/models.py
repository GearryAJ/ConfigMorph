from enum import StrEnum
from typing import Any
from pydantic import BaseModel, Field, field_validator
from app.core.migration.models import CompatibilityStatus

class ReviewStatus(StrEnum):
    NOT_REVIEWED="NOT_REVIEWED"; REVIEWED="REVIEWED"; ACCEPTED="ACCEPTED"; NEEDS_CHANGES="NEEDS_CHANGES"; BLOCKED="BLOCKED"

class ReviewDecision(BaseModel):
    status:ReviewStatus=ReviewStatus.NOT_REVIEWED
    note:str=""
    semantic_hash:str=""
    @field_validator("note")
    @classmethod
    def plain_note(cls,value):
        if len(value)>4000 or any(x in value for x in "\x00\r"): raise ValueError("invalid review note")
        return value

class MigrationReviewItem(BaseModel):
    id:str; entity_type:str; source_id:str; source_name:str; target_name:str|None=None
    compatibility_status:CompatibilityStatus; review_status:ReviewStatus=ReviewStatus.NOT_REVIEWED; note:str=""; semantic_hash:str
    source_semantics:dict[str,Any]=Field(default_factory=dict); target_semantics:dict[str,Any]=Field(default_factory=dict)
    preserved_fields:list[str]=Field(default_factory=list); changed_fields:dict[str,Any]=Field(default_factory=dict); dropped_fields:list[str]=Field(default_factory=list)
    manual_review_reasons:list[str]=Field(default_factory=list); warnings:list[str]=Field(default_factory=list)
    mapping_evidence:dict[str,Any]=Field(default_factory=dict); analysis_findings:list[dict[str,Any]]=Field(default_factory=list)
    generated_commands:list[dict[str,Any]]=Field(default_factory=list); used_by:list[dict[str,str]]=Field(default_factory=list); source_vendor:str|None=None

class ReviewSummary(BaseModel):
    total:int; generated:int; manual_review:int; unsupported:int; reviewed:int; accepted:int; needs_changes:int; blocked:int; manual_review_remaining:int

class MigrationReview(BaseModel):
    source_vendor:str; target_vendor:str; items:list[MigrationReviewItem]; summary:ReviewSummary

class ValidationSeverity(StrEnum): PASS="PASS"; WARNING="WARNING"; BLOCKING="BLOCKING"
class ValidationFinding(BaseModel): stage:str; severity:ValidationSeverity; code:str; message:str; entity_id:str|None=None
class ValidationReport(BaseModel):
    status:ValidationSeverity; findings:list[ValidationFinding]; stages:dict[str,ValidationSeverity]; application_validation_only:bool=True