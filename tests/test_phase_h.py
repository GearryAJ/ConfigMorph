import io,time,zipfile
from pathlib import Path
from fastapi.testclient import TestClient
from app.main import app
from app.core.models import Address,FirewallConfig,SecurityRule,Vendor
from app.core.migration import InterfaceMapping,MigrationMappings,MigrationPlanner
from app.core.renderers import PaloAltoRenderer
from app.core.review import ReviewDecision,ReviewStatus,build_review,export_package,semantic_hash,validate_migration

def mapped(zone="trust"):
    return MigrationMappings(interfaces=[InterfaceMapping(source_interface="Gi0/1",source_nameif="inside",target_interface="ethernet1/1",target_zone=zone,confirmed=True),InterfaceMapping(source_interface="Gi0/0",source_nameif="outside",target_interface="ethernet1/2",target_zone="untrust",confirmed=True)])

def config(count=1):
    return FirewallConfig(metadata={"source_vendor":Vendor.ASA},addresses=[Address(id=f"a{i}",name=f"A{i}",type="host",value=f"10.0.{i//250}.{i%250+1}") for i in range(count)],security_policies=[SecurityRule(id=f"r{i}",name=f"R{i}",position=i+1,source_zones=["inside"],destination_zones=["outside"],sources=[f"A{i}"],destinations=["any"],services=["any"],action="allow") for i in range(count)])

def reviewed(cfg=None,mappings=None,decisions=None):
    cfg=cfg or config(); plan=MigrationPlanner().plan(cfg,mappings or mapped()); renderer=PaloAltoRenderer(); lines,_=renderer.render(plan)
    return cfg,plan,lines,build_review(cfg,plan,renderer.commands,decisions)

def test_review_generation_hash_traceability_and_decisions():
    cfg,plan,lines,review=reviewed(); policy=next(x for x in review.items if x.id=="r0")
    assert policy.target_semantics=={} and not policy.generated_commands
    assert policy.analysis_findings and policy.used_by==[] and semantic_hash({"b":1,"a":2})==semantic_hash({"a":2,"b":1})
    decision={"r0":ReviewDecision(status=ReviewStatus.ACCEPTED,note="Confirmed with owner",semantic_hash=policy.semantic_hash)}
    accepted=build_review(cfg,plan,PaloAltoRenderer_with(plan),decision); assert next(x for x in accepted.items if x.id=="r0").review_status=="ACCEPTED"
    changed_plan=MigrationPlanner().plan(cfg,mapped("internal-zone")); commands=PaloAltoRenderer_with(changed_plan)
    changed=build_review(cfg,changed_plan,commands,decision); assert next(x for x in changed.items if x.id=="r0").review_status=="ACCEPTED"
    assert next(x for x in changed.items if x.id=="a0").semantic_hash==next(x for x in review.items if x.id=="a0").semantic_hash

def PaloAltoRenderer_with(plan):
    renderer=PaloAltoRenderer(); renderer.render(plan); return renderer.commands

def test_validation_accounting_warning_blocking_and_zip():
    cfg,plan,lines,review=reviewed(); validation=validate_migration(cfg,plan,review,lines)
    assert validation.status=="BLOCKING" and review.summary.generated+review.summary.manual_review+review.summary.unsupported==review.summary.total
    broken=review.model_copy(deep=True); broken.summary.generated-=1
    assert validate_migration(cfg,plan,broken,lines).status=="BLOCKING"
    package=export_package("candidate",{},review,validation,mapped()); names=zipfile.ZipFile(io.BytesIO(package)).namelist()
    assert {"candidate-pan-os.set","review-report.json","mappings.json"}<=set(names) and "source.cfg" not in names and all(".." not in x and not x.startswith(("/","\\")) for x in names)

def test_manual_and_unsupported_retained():
    cfg=FirewallConfig(metadata={"source_vendor":Vendor.ASA},addresses=[Address(id="bad",name="bad",type="any")])
    _,_,_,review=reviewed(cfg,mapped()); item=review.items[0]
    assert item.compatibility_status=="MANUAL_REVIEW" and not item.generated_commands

def test_review_api_persistence_invalidation_validation_and_package():
    client=TestClient(app); source=Path("examples/asa/basic.cfg").read_text(); response=client.post("/api/analyze",data={"source":source,"source_vendor":"cisco_asa","source_version":"9.20","target_vendor":"paloalto","target_version":"11.1"}); project=response.text.split("Project: <code>")[1].split("<")[0]; base=f"/api/projects/{project}/migration"
    mappings=client.get(base+"/mappings").json()
    for item in mappings["interfaces"]: item.update(target_interface="ethernet1/1",target_zone="untrust" if item["source_nameif"]=="outside" else "trust",confirmed=True)
    assert client.put(base+"/mappings",json=mappings).status_code==200; assert client.post(base+"/render").status_code==200
    review=client.get(base+"/review").json(); item=next(x for x in review["items"] if "/" not in x["id"])
    update={"status":"NEEDS_CHANGES","note":"Confirm with application owner.","semantic_hash":item["semantic_hash"]}
    assert client.put(base+f"/review/{item['id']}",json=update).json()["note"]==update["note"]
    assert client.put(base+f"/review/{item['id']}",json={**update,"semantic_hash":"stale"}).status_code==409
    assert client.get(base+f"/review/{item['id']}").json()["review_status"]=="NEEDS_CHANGES"
    validation=client.post(base+"/validate"); assert validation.status_code==200 and client.get(base+"/validation").status_code==200
    package=client.get(base+"/review-package"); assert package.status_code==200

def test_review_generation_2000_entities_linear_smoke():
    started=time.perf_counter(); *_,review=reviewed(config(1000),mapped())
    assert len(review.items)==2000 and time.perf_counter()-started<10