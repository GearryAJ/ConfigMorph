import pytest
import io,zipfile
from app.core.models import FirewallConfig,SecurityRule,Vendor
from app.core.migration import InterfaceMapping,MigrationMappings,MigrationPlanner,PolicyOrderingPlan,SecurityRuleOrderingAction,SecurityRulePlacement
from app.core.renderers import PaloAltoRenderer
from app.core.versions import resolve_context

def mappings(mode="BOTTOM",anchor=None):
    return MigrationMappings(security_rule_placement=SecurityRulePlacement(mode=mode,anchor_rule=anchor),interfaces=[InterfaceMapping(source_interface="inside",source_nameif="inside",target_zone="trust",confirmed=True),InterfaceMapping(source_interface="outside",source_nameif="outside",target_zone="untrust",confirmed=True)])

def config(vendor=Vendor.FORTIGATE,count=3):
    return FirewallConfig(metadata={"source_vendor":vendor},security_policies=[SecurityRule(id=f"r{i}",name=f"R{i}",position=i,source_zones=["inside"],destination_zones=["outside"],action="allow") for i in range(count,0,-1)])

def render(vendor=Vendor.FORTIGATE,count=3,mode="BOTTOM",anchor=None):
    cfg=config(vendor,count); source="7.4" if vendor==Vendor.FORTIGATE else "9.20"
    plan=MigrationPlanner().plan(cfg,mappings(mode,anchor),resolve_context("",vendor,source),resolve_context("",Vendor.PALO_ALTO,"11.1")); renderer=PaloAltoRenderer(); lines,report=renderer.render(plan)
    return plan,renderer,lines,report

@pytest.mark.parametrize("count",[1,2,3])
@pytest.mark.parametrize("mode,anchor",[("TOP",None),("BOTTOM",None),("BEFORE","existing-rule"),("AFTER","existing-rule")])
def test_order_plan_preserves_source_order_and_placement(count,mode,anchor):
    plan,renderer,lines,report=render(count=count,mode=mode,anchor=anchor)
    order=renderer.ordering_plan
    assert order.source_order==[f"R{i}" for i in range(1,count+1)]
    assert order.actions[0].relation==mode and order.actions[0].reference_rule==anchor
    assert [x.relation for x in order.actions[1:]]==["AFTER"]*(count-1)
    assert len(order.actions)==len([x for x in plan.generate if x.entity_type=="security_policy"])
    assert order.mechanism=="PANOS_CONFIG_API_MOVE" and order.documentation_refs==["PANOS-11.1-CONFIG-API-ACTIONS"]
    assert all(not line.startswith("move ") for line in lines) and report.security_rule_ordering==order

def test_missing_or_invalid_placement_blocks_policy():
    cfg=config(count=1); source=resolve_context("",Vendor.FORTIGATE,"7.4"); target=resolve_context("",Vendor.PALO_ALTO,"11.1")
    plan=MigrationPlanner().plan(cfg,MigrationMappings(),source,target)
    assert plan.compatibility[0].status=="MANUAL_REVIEW" and not plan.generate
    with pytest.raises(ValueError): SecurityRulePlacement(mode="BEFORE")
    with pytest.raises(ValueError): SecurityRulePlacement(mode="TOP",anchor_rule="x")

def test_duplicate_position_and_name_are_blocked():
    cfg=config(count=2); cfg.security_policies[1].position=cfg.security_policies[0].position
    plan=MigrationPlanner().plan(cfg,mappings(),resolve_context("",Vendor.FORTIGATE,"7.4"),resolve_context("",Vendor.PALO_ALTO,"11.1"))
    assert not plan.generate and all(x.status=="MANUAL_REVIEW" for x in plan.compatibility)
    plan,renderer,_,report=render(count=2); plan.generate[1].target_name=plan.generate[0].target_name
    renderer.render(plan); assert renderer.ordering_plan is None and "Duplicate generated" in renderer.render(plan)[1].errors[0]

def test_asa_fortigate_equivalent_order_parity():
    assert render(Vendor.ASA)[1].ordering_plan.source_order==render(Vendor.FORTIGATE)[1].ordering_plan.source_order

def test_unsupported_version_and_panorama_remain_blocked():
    cfg=config(count=1)
    plan=MigrationPlanner().plan(cfg,mappings(),resolve_context("",Vendor.FORTIGATE,"7.4"),resolve_context("",Vendor.PALO_ALTO,"12.1"))
    assert not plan.generate and plan.compatibility[0].status=="MANUAL_REVIEW"

def test_ordering_dto_rejects_duplicate_omission_cycle_and_unknown_rule():
    base=dict(target_profile="panos-11.1",placement=SecurityRulePlacement(mode="TOP"),source_order=["R1","R2"],documentation_refs=["PANOS-11.1-CONFIG-API-ACTIONS"])
    action=lambda name,relation,reference=None:SecurityRuleOrderingAction(rule_name=name,relation=relation,reference_rule=reference,target_profile="panos-11.1",documentation_refs=base["documentation_refs"])
    for actions in ([action("R1","TOP"),action("R1","AFTER","R1")],[action("R1","TOP")],[action("R1","TOP"),action("R2","AFTER","R2")],[action("R1","TOP"),action("R2","AFTER","unknown")]):
        with pytest.raises(ValueError): PolicyOrderingPlan(**base,actions=actions)

def test_review_package_exports_ordering_provenance():
    from app.core.review.report import export_package
    from tests.test_phase_h import reviewed
    _,renderer,_,report=render(count=1)
    _,_,_,review=reviewed(); validation=type("Validation",(),{"status":"PASS","findings":[],"model_dump_json":lambda self,indent=2:"{}"})()
    package=export_package("set rulebase security rules R1 action allow",report.model_dump(mode="json"),review,validation,mappings(),renderer.ordering_plan)
    archive=zipfile.ZipFile(io.BytesIO(package)); data=archive.read("security-rule-ordering.json").decode()
    assert "PANOS_CONFIG_API_MOVE" in data and "PANOS-11.1-CONFIG-API-ACTIONS" in data