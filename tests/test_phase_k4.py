import pytest

from app.core.migration import InterfaceMapping,MigrationMappings,MigrationPlanner,NatRouteOutcome,NatRulePlacement
from app.core.models import Vendor
from app.core.parsing import parse_config
from app.core.renderers import PaloAltoRenderer
from app.core.versions import PROFILES,evidence_state,resolve_context

MAP=MigrationMappings(interfaces=[
    InterfaceMapping(source_interface="inside",source_nameif="inside",target_interface="ethernet1/2",target_zone="trust",confirmed=True),
    InterfaceMapping(source_interface="outside",source_nameif="outside",target_interface="ethernet1/1",target_zone="untrust",confirmed=True),
])

@pytest.mark.parametrize("capability",["static_source_nat","dynamic_ip_and_port","interface_address_pat","destination_static_nat","destination_port_translation","identity_nat","twice_nat","ip_pool_snat","central_nat"])
def test_nat_capabilities_are_independent_and_incomplete(capability):
    target=PROFILES["panos-11.1"]
    assert capability in target.capabilities
    assert not evidence_state(PROFILES["asa-9.20"],target,capability).complete
    assert not PROFILES["panos-12.1"].capabilities[capability].documentation_refs

@pytest.mark.parametrize("source",[
    "object network WEB\n host 10.0.0.10\n nat (inside,outside) static 192.0.2.10\n",
    "object network LAN\n subnet 10.0.0.0 255.255.255.0\n nat (inside,outside) dynamic interface\n",
    "object network LAN\n subnet 10.0.0.0 255.255.255.0\n nat (inside,outside) static LAN\n",
    "nat (inside,outside) source static LAN XLATE destination static WEB WEB\n",
])
def test_asa_nat_subtypes_are_accounted_without_candidate(source):
    cfg=parse_config(source,Vendor.ASA)
    plan=MigrationPlanner().plan(cfg,MAP,resolve_context("",Vendor.ASA,"9.20"),resolve_context("",Vendor.PALO_ALTO,"11.1"))
    nat=[x for x in plan.compatibility if x.entity_type=="nat_policy"]
    assert len(nat)==len(cfg.nat_policies) and all(x.status in {"MANUAL_REVIEW","UNSUPPORTED","PARTIAL"} for x in nat)
    renderer=PaloAltoRenderer(); lines,_=renderer.render(plan)
    assert not any("rulebase nat" in line for line in lines)

def test_fortigate_pat_pool_central_and_vip_are_independently_accounted():
    text='''#config-version=FGT60F-7.4.0
set central-nat enable
config firewall policy
 edit 1
  set srcintf "inside"
  set dstintf "outside"
  set srcaddr "all"
  set dstaddr "all"
  set service "ALL"
  set nat enable
  set ippool enable
  set poolname "POOL"
 next
end
config firewall vip
 edit "HTTPS"
  set extip 192.0.2.10
  set mappedip 10.0.0.10
  set extintf "outside"
  set portforward enable
  set protocol tcp
  set extport 443
  set mappedport 8443
 next
end'''
    cfg=parse_config(text,Vendor.FORTIGATE)
    plan=MigrationPlanner().plan(cfg,MAP,resolve_context("",Vendor.FORTIGATE,"7.4"),resolve_context("",Vendor.PALO_ALTO,"11.1"))
    nat=[x for x in plan.compatibility if x.entity_type=="nat_policy"]
    assert len(nat)==2 and all(x.status=="MANUAL_REVIEW" for x in nat)
    assert any("Central NAT" in " ".join(x.reasons) for x in nat)

def test_no_generated_nat_entity_or_command_without_complete_evidence():
    cfg=parse_config("object network LAN\n subnet 10.0.0.0 255.255.255.0\n nat (inside,outside) dynamic interface\n",Vendor.ASA)
    plan=MigrationPlanner().plan(cfg,MAP,resolve_context("",Vendor.ASA,"9.20"),resolve_context("",Vendor.PALO_ALTO,"11.1"))
    assert not [x for x in plan.generate if x.entity_type=="nat_policy"]
    renderer=PaloAltoRenderer(); renderer.render(plan)
    assert not [x for x in renderer.commands if "nat" in x.path]

@pytest.mark.parametrize("capability",["dynamic_ip_and_port","interface_address_pat","destination_static_nat"])
def test_panos_111_target_nat_semantics_are_independently_verified(capability):
    state=evidence_state(PROFILES["asa-9.20"],PROFILES["panos-11.1"],capability)
    assert state.target_match_semantics_documented and state.target_translation_semantics_documented
    assert state.route_lookup_semantics_documented
    assert not state.ordering_verified and not state.placement_verified and not state.complete

def test_dnat_evidence_distinguishes_pre_nat_match_from_post_nat_security_zone():
    capability=PROFILES["panos-11.1"].capabilities["destination_static_nat"]
    assert "PANOS-11.1-DNAT-ONE-TO-ONE" in capability.documentation_refs
    cfg=parse_config('''#config-version=FGT60F-7.4.0
config firewall vip
 edit "WEB"
  set extip 192.0.2.10
  set mappedip 10.0.0.10
  set extintf "outside"
 next
end''',Vendor.FORTIGATE)
    cfg.nat_policies[0].source_zones=["outside"]
    cfg.nat_policies[0].destination_zones=["inside"]
    plan=MigrationPlanner().plan(cfg,MAP,resolve_context("",Vendor.FORTIGATE,"7.4"),resolve_context("",Vendor.PALO_ALTO,"11.1"))
    reason=" ".join(next(x for x in plan.compatibility if x.entity_type=="nat_policy").reasons)
    assert "destination-zone route-lookup semantics: Verified" in reason
    assert "explicit route outcome: Not verified" in reason
    assert "ordering: Not verified" in reason and "placement: Not verified" in reason
    assert not [x for x in plan.generate if x.entity_type=="nat_policy"]

def test_port_translation_target_semantics_remain_unverified():
    state=evidence_state(PROFILES["fortios-7.4"],PROFILES["panos-11.1"],"destination_port_translation")
    assert not state.target_match_semantics_documented
    assert not state.target_translation_semantics_documented
    assert not state.route_lookup_semantics_documented

def test_panos_121_does_not_inherit_nat_semantic_evidence():
    state=evidence_state(PROFILES["asa-9.20"],PROFILES["panos-12.1"],"dynamic_ip_and_port")
    assert not state.target_match_semantics_documented
    assert not state.target_translation_semantics_documented
    assert not state.route_lookup_semantics_documented

def test_nat_placement_and_route_outcome_contracts_are_explicit_but_do_not_enable_generation():
    with pytest.raises(ValueError): NatRulePlacement(mode="BEFORE")
    with pytest.raises(ValueError): NatRulePlacement(mode="TOP",anchor_rule="existing")
    outcome=NatRouteOutcome(nat_rule="nat-3",nat_from_zone="untrust",nat_pre_translation_to_zone="untrust",security_post_translation_to_zone="trust",confirmed=True)
    mappings=MAP.model_copy(update={"nat_rule_placement":NatRulePlacement(mode="BOTTOM"),"nat_route_outcomes":[outcome]})
    cfg=parse_config("object network LAN\n subnet 10.0.0.0 255.255.255.0\n nat (inside,outside) dynamic interface\n",Vendor.ASA)
    plan=MigrationPlanner().plan(cfg,mappings,resolve_context("",Vendor.ASA,"9.20"),resolve_context("",Vendor.PALO_ALTO,"11.1"))
    assert not [x for x in plan.generate if x.entity_type=="nat_policy"]

def test_asa_nat_effective_order_uses_section_then_source_sequence():
    cfg=parse_config("object network LAN\n host 10.0.0.1\n nat (inside,outside) dynamic interface\nnat (inside,outside) source static LAN LAN\nnat (inside,outside) after-auto source dynamic LAN interface\n",Vendor.ASA)
    adapted=__import__("app.core.migration.sources.cisco_asa",fromlist=["CiscoAsaSourceAdapter"]).CiscoAsaSourceAdapter().adapt(cfg)
    assert [x.vendor_extensions["section"] for x in adapted.nat_policies]==[1,2,3]
    assert [x.position for x in adapted.nat_policies]==[1,2,3]

def test_fortigate_vip_uses_unique_referencing_policy_context():
    cfg=parse_config('''#config-version=FGT60F-7.4.0
config firewall policy
 edit 7
  set srcintf "outside"
  set dstintf "inside"
  set dstaddr "WEB"
 next
end
config firewall vip
 edit "WEB"
  set extip 192.0.2.10
  set mappedip 10.0.0.10
 next
end''',Vendor.FORTIGATE)
    adapted=__import__("app.core.migration.sources.fortigate",fromlist=["FortiGateSourceAdapter"]).FortiGateSourceAdapter().adapt(cfg)
    assert adapted.nat_policies[0].source_zones==["outside"]
    assert adapted.nat_policies[0].destination_zones==["inside"]
    assert adapted.nat_policies[0].vendor_extensions["policy"]=="7"