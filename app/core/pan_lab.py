import hashlib
import re
import secrets
import time
from datetime import datetime, timezone
from enum import StrEnum
from pathlib import Path
from typing import Protocol

from pydantic import BaseModel, Field, model_validator

from app.core.migration.models import PanSetCommand, TargetManagementMode

DOCUMENTATION_REFS=["PANOS-11.1-MANAGE-BACKUPS","PANOS-11.1-SAVE-CANDIDATE","PANOS-11.1-LOAD-SNAPSHOT","PANOS-11.1-XML-API-OP","PANOS-11.1-XML-API-CONFIG"]

class PanLabStatus(StrEnum):
    PASS="PASS"; WARNING="WARNING"; BLOCKING="BLOCKING"; ERROR="ERROR"; VERSION_MISMATCH="VERSION_MISMATCH"

class CleanupStatus(StrEnum):
    NOT_REQUIRED="NOT_REQUIRED"; RESTORED="RESTORED"; RESTORE_FAILED="RESTORE_FAILED"; RESTORE_UNVERIFIED="RESTORE_UNVERIFIED"

class PanLabError(StrEnum):
    SNAPSHOT_SAVE_FAILED="SNAPSHOT_SAVE_FAILED"; CANDIDATE_APPLY_FAILED="CANDIDATE_APPLY_FAILED"; VALIDATION_FAILED="VALIDATION_FAILED"
    RESTORE_FAILED="RESTORE_FAILED"; RESTORE_UNVERIFIED="RESTORE_UNVERIFIED"; VERSION_MISMATCH="VERSION_MISMATCH"; CONNECTION_ERROR="CONNECTION_ERROR"

class PanLabOperation(StrEnum):
    SHOW_VERSION="SHOW_VERSION"; SAVE_CANDIDATE="SAVE_CANDIDATE"; APPLY_CANDIDATE="APPLY_CANDIDATE"
    VALIDATE_FULL="VALIDATE_FULL"; LOAD_SNAPSHOT="LOAD_SNAPSHOT"; VERIFY_CANDIDATE="VERIFY_CANDIDATE"

_DENIED=re.compile(r"(?:^|[^a-z])(?:commit(?:-all|-and-push)?|push|deploy)(?:$|[^a-z])",re.I)
_NAT=re.compile(r"^set\s+(?:vsys\s+\S+\s+)?rulebase\s+nat\s+rules\b",re.I)

def assert_safe_request(operation:PanLabOperation,payload:str=""):
    if operation not in PanLabOperation or _DENIED.search(payload): raise ValueError("PAN lab operation denied")

def snapshot_name(now:datetime|None=None)->str:
    stamp=(now or datetime.now(timezone.utc)).strftime("%Y%m%dT%H%M%SZ")
    return f"convert-in-validation-{stamp}-{secrets.token_hex(8)}.xml"

class PanLabMessage(BaseModel):
    category:str; message:str; command_index:int|None=None; entity_id:str|None=None
    capability_id:str|None=None; documentation_refs:list[str]=Field(default_factory=list)

class PanLabValidationResult(BaseModel):
    status:PanLabStatus; error_state:PanLabError|None=None; cleanup_status:CleanupStatus=CleanupStatus.NOT_REQUIRED
    target_profile:str="panos-11.1"; device_version:str|None=None; validation_method:str="PAN-OS XML API validate full"
    started_at:str; duration_ms:int; candidate_hash:str; snapshot_name_hash:str|None=None
    syntax_errors:list[PanLabMessage]=Field(default_factory=list); reference_errors:list[PanLabMessage]=Field(default_factory=list)
    device_messages:list[str]=Field(default_factory=list); snapshot_created:bool=False; candidate_loaded:bool=False
    preexisting_candidate_preserved:bool=False; restore_attempted:bool=False; restore_succeeded:bool=False
    restore_verified:bool=False; temporary_snapshot_cleanup:str="NOT_ATTEMPTED_UNDOCUMENTED"; commit_performed:bool=False
    documentation_refs:list[str]=Field(default_factory=lambda:list(DOCUMENTATION_REFS))
    @model_validator(mode="after")
    def safety_invariants(self):
        if self.commit_performed: raise ValueError("PAN lab validation cannot perform commits")
        if self.status in {PanLabStatus.PASS,PanLabStatus.WARNING} and self.cleanup_status!=CleanupStatus.RESTORED: raise ValueError("Successful validation requires verified restoration")
        return self

class PanLabTransport(Protocol):
    def version(self)->str: ...
    def candidate_state(self)->str: ...
    def save_candidate(self,name:str)->None: ...
    def verify_snapshot(self,name:str)->bool: ...
    def apply(self,commands:list[str])->None: ...
    def validate(self)->list[dict]: ...
    def load_snapshot(self,name:str)->None: ...

def validate_in_lab(candidate:str,commands:list[PanSetCommand],management_mode:TargetManagementMode,transport:PanLabTransport)->PanLabValidationResult:
    started=datetime.now(timezone.utc).isoformat(); clock=time.perf_counter(); digest=hashlib.sha256(candidate.encode()).hexdigest()
    values={"device_version":None,"snapshot_name_hash":None,"snapshot_created":False,"candidate_loaded":False,"preexisting_candidate_preserved":False,"restore_attempted":False,"restore_succeeded":False,"restore_verified":False,"cleanup_status":CleanupStatus.NOT_REQUIRED,"error_state":None,"syntax_errors":[],"reference_errors":[],"device_messages":[]}
    def result(status): return PanLabValidationResult(status=status,started_at=started,duration_ms=round((time.perf_counter()-clock)*1000),candidate_hash=digest,**values)
    if management_mode!=TargetManagementMode.LOCAL_FIREWALL: values["device_messages"]=["Panorama validation is unsupported."]; return result(PanLabStatus.BLOCKING)
    lines=[x for x in candidate.splitlines() if x.strip()]
    if any(_NAT.match(x) for x in lines): values["device_messages"]=["Unexpected NAT command blocked before device connection."]; return result(PanLabStatus.BLOCKING)
    if lines!=[x.text for x in commands]: values["device_messages"]=["Candidate command provenance is incomplete."]; return result(PanLabStatus.BLOCKING)
    name=snapshot_name(); values["snapshot_name_hash"]=hashlib.sha256(name.encode()).hexdigest(); before=None; mutation_possible=False; status=PanLabStatus.ERROR
    try:
        values["device_version"]=transport.version()
        if not values["device_version"].startswith("11.1"):
            values["error_state"]=PanLabError.VERSION_MISMATCH; return result(PanLabStatus.VERSION_MISMATCH)
        before=transport.candidate_state()
        try:
            transport.save_candidate(name)
            if not transport.verify_snapshot(name): raise RuntimeError("snapshot verification failed")
            values["snapshot_created"]=True
        except Exception:
            values["error_state"]=PanLabError.SNAPSHOT_SAVE_FAILED; return result(PanLabStatus.ERROR)
        mutation_possible=True
        try: transport.apply(lines); values["candidate_loaded"]=True
        except Exception: values["error_state"]=PanLabError.CANDIDATE_APPLY_FAILED; status=PanLabStatus.ERROR
        else:
            try: raw=transport.validate()
            except Exception: values["error_state"]=PanLabError.VALIDATION_FAILED; status=PanLabStatus.ERROR
            else:
                correlated=[]
                for item in raw:
                    index=item.get("command_index"); command=commands[index] if isinstance(index,int) and 0<=index<len(commands) else None
                    correlated.append(PanLabMessage(category=item.get("category","device"),message=item.get("message","Device validation error"),command_index=index,entity_id=command.entity_id if command else None,capability_id=command.capability_id if command else None,documentation_refs=command.documentation_refs if command else []))
                values["syntax_errors"]=[x for x in correlated if x.category=="syntax"]; values["reference_errors"]=[x for x in correlated if x.category=="reference"]
                status=PanLabStatus.BLOCKING if values["syntax_errors"] or values["reference_errors"] else PanLabStatus.WARNING if correlated else PanLabStatus.PASS
    except Exception as exc:
        values["error_state"]=PanLabError.CONNECTION_ERROR; values["device_messages"]=[f"Connection error: {type(exc).__name__}"]
    finally:
        if mutation_possible:
            values["restore_attempted"]=True
            try:
                transport.load_snapshot(name); values["restore_succeeded"]=True
                values["restore_verified"]=transport.candidate_state()==before
                if values["restore_verified"]:
                    values["cleanup_status"]=CleanupStatus.RESTORED; values["preexisting_candidate_preserved"]=True
                else:
                    values["cleanup_status"]=CleanupStatus.RESTORE_UNVERIFIED; values["error_state"]=PanLabError.RESTORE_UNVERIFIED; status=PanLabStatus.BLOCKING
            except Exception:
                values["cleanup_status"]=CleanupStatus.RESTORE_FAILED; values["error_state"]=PanLabError.RESTORE_FAILED; status=PanLabStatus.BLOCKING
    return result(status)

def persist_result(root:Path,result:PanLabValidationResult):
    path=root/"validation"/"pan-lab-validation.json"; path.parent.mkdir(exist_ok=True)
    temp=path.with_suffix(".tmp"); temp.write_text(result.model_dump_json(indent=2),encoding="utf-8"); temp.replace(path)
    return path