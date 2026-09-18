import pytest
from fastapi.testclient import TestClient
from app.main import app
from app.core.analysis import AnalysisEngine
from app.core.migration import MigrationPlanner,default_mappings
from app.core.migration.models import SecurityRulePlacement
from app.core.models import Vendor
from app.core.parsing import parse_config
from app.core.renderers import PaloAltoRenderer
from app.core.versions import resolve_context
from app.testing.realistic_fixtures import asa,fortigate

def run(vendor,text):
    cfg=parse_config(text,vendor); AnalysisEngine().analyze(cfg); mappings=default_mappings(cfg)
    for i,m in enumerate(mappings.interfaces): m.target_interface=f"ethernet1/{i+1}"; m.target_zone=m.source_nameif; m.confirmed=True
    mappings.security_rule_placement=SecurityRulePlacement(mode="BOTTOM")
    source="9.20" if vendor is Vendor.ASA else "7.4"
    plan=MigrationPlanner().plan(cfg,mappings,resolve_context(text,vendor,source),resolve_context("",Vendor.PALO_ALTO,"11.1")); renderer=PaloAltoRenderer(); lines,report=renderer.render(plan)
    return cfg,plan,lines,report,renderer.ordering_plan

@pytest.mark.parametrize("vendor,builder",[(Vendor.ASA,asa),(Vendor.FORTIGATE,fortigate)])
@pytest.mark.parametrize("tier",["small","medium","large"])
def test_realistic_determinism_order_nat_and_collisions(vendor,builder,tier):
    first=run(vendor,builder(tier)); second=run(vendor,builder(tier))
    semantic=lambda result:(result[0].model_dump(mode="json"),result[1].model_dump(mode="json"),result[2],result[3].model_dump(mode="json",exclude={"generated_at"}),result[4].model_dump(mode="json") if result[4] else None)
    assert semantic(first)==semantic(second),f"{vendor.value}/{tier}: semantic output differs"
    cfg,plan,lines,report,ordering=first
    assert [x.position for x in cfg.security_policies]==sorted(x.position for x in cfg.security_policies),f"{vendor.value}/{tier}: policy order"
    generated_order=[x.target_name for x in plan.generate if x.entity_type=="security_policy"]
    if generated_order: assert ordering and ordering.source_order==generated_order
    else: assert [x.source_name for x in report.compatibility if x.entity_type=="security_policy"]==[x.name for x in cfg.security_policies]
    assert not any(" rulebase nat rules " in x for x in lines)
    assert all(x.status=="MANUAL_REVIEW" for x in report.compatibility if x.entity_type=="nat_policy")
    targets=[x.target_name.casefold() for x in plan.names]; assert len(targets)==len(set(targets)) and any(x.collision for x in plan.names)
    assert cfg.warnings and any("Unresolved" in x.message for x in cfg.warnings)

@pytest.mark.parametrize("vendor,text",[(Vendor.ASA,"ASA Version 9.20\n! malformed synthetic\nobject network BAD\n subnet 10.0.0.0 999.0.0.0\nobject-group network OPEN\n group-object MISSING\nunknown command\n"),(Vendor.FORTIGATE,'#config-version=FGT60F-7.4.0-FW-build0000-000000\n# malformed synthetic\nconfig firewall address\n edit "BAD\n set subnet 10.0.0.0 999.0.0.0\n unknown command\n')])
def test_malformed_partial_recovers(vendor,text):
    cfg=parse_config(text,vendor); assert cfg.warnings or cfg.unparsed_constructs

@pytest.mark.parametrize("vendor,builder,version",[("cisco_asa",asa,"9.20"),("fortigate",fortigate,"7.4")])
def test_realistic_api_e2e_and_export(vendor,builder,version):
    client=TestClient(app); response=client.post("/api/analyze",data={"source":builder("small"),"source_vendor":vendor,"source_version":version,"target_vendor":"paloalto","target_version":"11.1"}); assert response.status_code==200
    project=response.text.split("Project: <code>")[1].split("<")[0]; base=f"/api/projects/{project}/migration"; mappings=client.get(base+"/mappings").json()
    mappings["security_rule_placement"]={"mode":"BOTTOM","anchor_rule":None}
    for i,m in enumerate(mappings["interfaces"]): m.update(target_interface=f"ethernet1/{i+1}",target_zone=m["source_nameif"],confirmed=True)
    assert client.put(base+"/mappings",json=mappings).status_code==200
    assert client.post(base+"/plan").status_code==200 and client.post(base+"/render").status_code==200
    assert client.get(base+"/review").status_code==200 and client.post(base+"/validate").status_code==200
    package=client.get(base+"/review-package"); assert package.status_code==409