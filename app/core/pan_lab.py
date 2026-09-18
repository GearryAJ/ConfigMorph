import hashlib
import re
import time
from datetime import datetime, timezone
from enum import StrEnum
from pathlib import Path
from typing import Protocol

from pydantic import BaseModel, Field, model_validator

from app.core.migration.models import PanSetCommand, TargetManagementMode

DOCUMENTATION_REFS=["PANOS-11.1-CLI-VALIDATE","PANOS-11.1-CLI-LOAD-TEXT","PANOS-11.1-XML-API-ACTIONS"]

class PanLabStatus(StrEnum):
    PASS="PASS"; WARNING="WARNING"; BLOCKING="BLOCKING"; ERROR="ERROR"; VERSION_MISMATCH="VERSION_MISMATCH"

class PanLabMessage(BaseModel):
    category:str; message:str; command_index:int|None=None; entity_id:str|None=None
    capability_id:str|None=None; documentation_refs:list[str]=Field(default_factory=list)

class PanLabValidationResult(BaseModel):
    status:PanLabStatus; target_profile:str="panos-11.1"; device_version:str|None=None
    validation_method:str="PAN-OS CLI validate full"; started_at:str; duration_ms:int
    candidate_hash:str; syntax_errors:list[PanLabMessage]=Field(default_factory=list)
    reference_errors:list[PanLabMessage]=Field(default_factory=list)
    device_messages:list[str]=Field(default_factory=list); candidate_loaded:bool=False
    candidate_reverted:bool=False; revert_verified:bool=False; commit_performed:bool=False
    documentation_refs:list[str]=Field(default_factory=lambda:list(DOCUMENTATION_REFS))
    @model_validator(mode="after")
    def no_commit(self):
        if self.commit_performed: raise ValueError("PAN lab validation cannot perform commits")
        return self

class PanLabTransport(Protocol):
    def version(self)->str: ...
    def snapshot(self)->str: ...
    def apply(self,commands:list[str])->None: ...
    def validate(self)->list[dict]: ...
    def revert(self,snapshot:str)->None: ...
    def verify_revert(self,snapshot:str)->bool: ...

_NAT=re.compile(r"^set\s+(?:vsys\s+\S+\s+)?rulebase\s+nat\s+rules\b",re.I)

def validate_in_lab(candidate:str,commands:list[PanSetCommand],management_mode:TargetManagementMode,transport:PanLabTransport)->PanLabValidationResult:
    started=datetime.now(timezone.utc).isoformat(); clock=time.perf_counter(); digest=hashlib.sha256(candidate.encode()).hexdigest()
    def result(status,**values): return PanLabValidationResult(status=status,started_at=started,duration_ms=round((time.perf_counter()-clock)*1000),candidate_hash=digest,**values)
    if management_mode!=TargetManagementMode.LOCAL_FIREWALL: return result(PanLabStatus.BLOCKING,device_messages=["Panorama validation is unsupported."])
    lines=[x for x in candidate.splitlines() if x.strip()]
    if any(_NAT.match(x) for x in lines): return result(PanLabStatus.BLOCKING,device_messages=["Unexpected NAT command blocked before device connection."])
    if lines!=[x.text for x in commands]: return result(PanLabStatus.BLOCKING,device_messages=["Candidate command provenance is incomplete."])
    loaded=False; snapshot=None; version=None; messages=[]
    try:
        version=transport.version()
        if not version.startswith("11.1"): return result(PanLabStatus.VERSION_MISMATCH,device_version=version,device_messages=["Lab device version does not match PAN-OS 11.1 target profile."])
        snapshot=transport.snapshot(); transport.apply(lines); loaded=True
        raw=transport.validate()
        correlated=[]
        for item in raw:
            index=item.get("command_index"); command=commands[index] if isinstance(index,int) and 0<=index<len(commands) else None
            correlated.append(PanLabMessage(category=item.get("category","device"),message=item.get("message","Device validation error"),command_index=index,entity_id=command.entity_id if command else None,capability_id=command.capability_id if command else None,documentation_refs=command.documentation_refs if command else []))
        syntax=[x for x in correlated if x.category=="syntax"]; references=[x for x in correlated if x.category=="reference"]
        status=PanLabStatus.BLOCKING if syntax or references else PanLabStatus.WARNING if correlated else PanLabStatus.PASS
    except Exception as exc:
        status=PanLabStatus.ERROR; syntax=[]; references=[]; messages=[f"Connection or validation error: {type(exc).__name__}"]
    reverted=False
    if snapshot is not None:
        try: transport.revert(snapshot); reverted=transport.verify_revert(snapshot)
        except Exception: reverted=False
    if loaded and not reverted:
        status=PanLabStatus.BLOCKING; messages.append("Candidate datastore cleanup could not be confirmed. Engineer intervention required.")
    return result(status,device_version=version,syntax_errors=syntax,reference_errors=references,device_messages=messages,candidate_loaded=loaded,candidate_reverted=reverted,revert_verified=reverted)

def persist_result(root:Path,result:PanLabValidationResult):
    path=root/"validation"/"pan-lab-validation.json"; path.parent.mkdir(exist_ok=True)
    temp=path.with_suffix(".tmp"); temp.write_text(result.model_dump_json(indent=2),encoding="utf-8"); temp.replace(path)
    return path