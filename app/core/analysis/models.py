from enum import StrEnum
from typing import Any
from pydantic import BaseModel, Field
from app.core.models import Severity
from app.core.graph.models import GraphNode

class Confidence(StrEnum): HIGH="HIGH"; MEDIUM="MEDIUM"; LOW="LOW"
class FindingType(StrEnum):
    UNRESOLVED_REFERENCE="UNRESOLVED_REFERENCE"; UNUSED_OBJECT="UNUSED_OBJECT"; ORPHAN_GROUP="ORPHAN_GROUP"; EMPTY_GROUP="EMPTY_GROUP"; DUPLICATE_OBJECT="DUPLICATE_OBJECT"; POTENTIAL_DUPLICATE_POLICY="POTENTIAL_DUPLICATE_POLICY"; DISABLED_RULE="DISABLED_RULE"; ANY_SOURCE="ANY_SOURCE"; ANY_DESTINATION="ANY_DESTINATION"; ANY_SERVICE="ANY_SERVICE"; ANY_ANY_RULE="ANY_ANY_RULE"; POTENTIAL_SHADOWING="POTENTIAL_SHADOWING"; GROUP_CYCLE="GROUP_CYCLE"; ANALYZER_WARNING="ANALYZER_WARNING"; UNATTACHED_ACL="UNATTACHED_ACL"; AMBIGUOUS_POLICY_TOPOLOGY="AMBIGUOUS_POLICY_TOPOLOGY"; UNRESOLVED_POLICY_TOPOLOGY="UNRESOLVED_POLICY_TOPOLOGY"; UNSUPPORTED_SERVICE_OPERATOR="UNSUPPORTED_SERVICE_OPERATOR"; AMBIGUOUS_NAT="AMBIGUOUS_NAT"
class RelatedObject(BaseModel): type:str; id:str; name:str
class AnalysisFinding(BaseModel):
    id:str; type:FindingType; severity:Severity; title:str; description:str; primary_object_type:str; primary_object_id:str; primary_object_name:str; related_objects:list[RelatedObject]=Field(default_factory=list); evidence:dict[str,Any]=Field(default_factory=dict); recommendation:str|None=None; confidence:Confidence=Confidence.HIGH
class AnalysisCounts(BaseModel):
    unused_objects:int=0; duplicate_objects:int=0; unresolved_references:int=0; empty_groups:int=0; orphan_groups:int=0; disabled_rules:int=0; broad_rules:int=0; duplicate_policies:int=0; potential_shadowing:int=0; group_cycles:int=0; total_findings:int=0; info:int=0; warning:int=0; error:int=0
class AnalysisReport(BaseModel): counts:AnalysisCounts; findings:list[AnalysisFinding]; analyzer_warnings:list[str]=Field(default_factory=list)
class ImpactResult(BaseModel):
    object:GraphNode; direct_references:int; recursive_references:int; security_policies:list[GraphNode]; nat_policies:list[GraphNode]; groups:list[GraphNode]; routes:list[GraphNode]; impact_level:str; dependency_chains:list[list[str]]=Field(default_factory=list)