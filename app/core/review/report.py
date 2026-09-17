import io,json,zipfile
from pathlib import Path
from .models import ReviewDecision

def load_decisions(root:Path):
    path=root/"review.json"
    if not path.is_file(): return {}
    return {k:ReviewDecision.model_validate(v) for k,v in json.loads(path.read_text(encoding="utf-8")).items()}

def save_decisions(root:Path,decisions):
    path=root/"review.json"; temp=path.with_suffix(".tmp")
    temp.write_text(json.dumps({k:v.model_dump(mode="json") for k,v in decisions.items()},indent=2),encoding="utf-8"); temp.replace(path)

def human_report(review,validation,mappings):
    sections=["Migration Summary",f"Source: {review.source_vendor}\nTarget: {review.target_vendor}\nEntities: {review.summary.total}\nGenerated: {review.summary.generated}","Confirmed Mappings"]
    sections.append("\n".join(f"{x.source_nameif or x.source_interface} -> {x.target_zone} ({x.target_interface})" for x in mappings.interfaces if x.confirmed) or "None")
    for title,predicate in (("Converted Objects",lambda x:x.entity_type in {"address","address_group","service","service_group"} and x.generated_commands),("Converted Policies",lambda x:x.entity_type=="security_policy" and x.generated_commands),("Converted NAT",lambda x:x.entity_type=="nat_policy" and x.generated_commands),("Manual Review Items",lambda x:x.compatibility_status=="MANUAL_REVIEW"),("Unsupported Items",lambda x:x.compatibility_status=="UNSUPPORTED")):
        sections.extend([title,"\n".join(f"- {x.source_name}: {', '.join(x.manual_review_reasons) or x.compatibility_status}" for x in review.items if predicate(x)) or "None"])
    sections.extend(["Validation Results",f"Application-level validation: {validation.status}\n"+"\n".join(f"- {x.severity} {x.code}: {x.message}" for x in validation.findings),"Engineer Review Decisions","\n".join(f"- {x.source_name}: {x.review_status} {x.note}" for x in review.items if x.review_status!="NOT_REVIEWED") or "None","Known Limitations","Candidate only. Engineer review required. Not validated by PAN-OS. No deployment capability. Advanced NAT and IPv6 topology remain review-only."])
    return "\n\n".join(f"## {x}" if i%2==0 else x for i,x in enumerate(sections))+"\n"

def export_package(candidate,report,review,validation,mappings):
    files={"candidate-pan-os.set":candidate,"migration-report.json":json.dumps(report,indent=2,default=str),"review-report.json":review.model_dump_json(indent=2),"validation-report.json":validation.model_dump_json(indent=2),"mappings.json":mappings.model_dump_json(indent=2),"README.txt":"CANDIDATE CONFIGURATION ONLY\nEngineer review required. Application-level validation is not PAN-OS/device validation. No source configuration is included.\n","migration-report.md":human_report(review,validation,mappings)}
    output=io.BytesIO()
    with zipfile.ZipFile(output,"w",zipfile.ZIP_DEFLATED) as archive:
        for name,value in files.items(): archive.writestr(name,value)
    return output.getvalue()