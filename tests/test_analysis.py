from app.core.analysis import AnalysisEngine, FindingType
from app.core.graph import DependencyGraphBuilder, EdgeType, find_path, get_dependencies, get_recursive_dependents, resolve_node, serialize_graph
from app.core.models import Address, FirewallConfig, NatRule, SecurityRule, Service, Zone, Interface

def fixture():
    return FirewallConfig(
        interfaces=[Interface(id="eth1",name="eth1")], zones=[Zone(id="LAN",name="LAN",interfaces=["eth1"]),Zone(id="WAN",name="WAN")],
        addresses=[Address(id="net",name="net",type="network",value="10.0.0.0/8"),Address(id="web",name="web",type="host",value="10.1.1.1/32"),Address(id="web-copy",name="web-copy",type="host",value="10.1.1.1/32"),Address(id="unused",name="unused",type="host",value="192.0.2.1/32")],
        address_groups=[Address(id="servers",name="servers",type="group",members=["web"]),Address(id="nested",name="nested",type="group",members=["servers"]),Address(id="orphan",name="orphan",type="group",members=["unused"]),Address(id="empty",name="empty",type="group",members=["missing"]),Address(id="cycle-a",name="cycle-a",type="group",members=["cycle-b"]),Address(id="cycle-b",name="cycle-b",type="group",members=["cycle-a"])],
        services=[Service(id="https",name="https",protocol="tcp",destination_ports=["443"]),Service(id="https-copy",name="https-copy",protocol="tcp",destination_ports=["443"])],
        security_policies=[
            SecurityRule(id="broad",name="broad",position=1,source_zones=["LAN"],destination_zones=["WAN"],sources=["any"],destinations=["net"],services=["any"],action="allow"),
            SecurityRule(id="specific",name="specific",position=2,source_zones=["LAN"],destination_zones=["WAN"],sources=["web"],destinations=["web"],services=["https"],action="allow"),
            SecurityRule(id="duplicate",name="duplicate",position=3,source_zones=["LAN"],destination_zones=["WAN"],sources=["web"],destinations=["web"],services=["https"],action="allow"),
            SecurityRule(id="disabled",name="disabled",position=4,sources=["broken"],enabled=False)],
        nat_policies=[NatRule(id="nat",name="nat",type="destination_nat",original_destination=["nested"],translated_destination=["web"])])

def types(report): return [x.type for x in report.findings]

def test_graph_queries_preserve_semantic_edges():
    graph=DependencyGraphBuilder().build(fixture()); policy=resolve_node(graph,"specific"); web=resolve_node(graph,"web")
    assert web in get_dependencies(graph,policy)
    assert policy in get_recursive_dependents(graph,web)
    assert find_path(graph,policy,web)==[policy,web]
    edges=[x.type for x in serialize_graph(graph).edges if x.source==policy and x.target==web]
    assert set(edges)=={EdgeType.USES_SOURCE,EdgeType.USES_DESTINATION}

def test_analysis_features_and_impact():
    report,graph=AnalysisEngine().analyze(fixture()); found=types(report)
    for expected in (FindingType.UNRESOLVED_REFERENCE,FindingType.UNUSED_OBJECT,FindingType.ORPHAN_GROUP,FindingType.EMPTY_GROUP,FindingType.DUPLICATE_OBJECT,FindingType.POTENTIAL_DUPLICATE_POLICY,FindingType.DISABLED_RULE,FindingType.ANY_SOURCE,FindingType.POTENTIAL_SHADOWING,FindingType.GROUP_CYCLE): assert expected in found
    impact=AnalysisEngine().impact(graph,"web")
    assert impact.impact_level=="HIGH" and {x.name for x in impact.security_policies}=={"specific","duplicate"} and impact.nat_policies
    assert AnalysisEngine().impact(graph,"not-there") is None

def test_uncertain_fqdn_not_shadowed():
    cfg=FirewallConfig(addresses=[Address(id="a",name="a",type="fqdn",value="*.example.com"),Address(id="b",name="b",type="fqdn",value="www.example.com")],security_policies=[SecurityRule(id="a-rule",name="a-rule",position=1,sources=["a"]),SecurityRule(id="b-rule",name="b-rule",position=2,sources=["b"])])
    assert FindingType.POTENTIAL_SHADOWING not in types(AnalysisEngine().analyze(cfg)[0])

def test_scalability_1000_objects_and_rules():
    cfg=FirewallConfig(addresses=[Address(id=f"a{i}",name=f"a{i}",type="host",value=f"10.{i//65536}.{(i//256)%256}.{i%256}/32") for i in range(1000)],address_groups=[Address(id=f"g{i}",name=f"g{i}",type="group",members=[f"a{i*10+j}" for j in range(10)]) for i in range(100)],security_policies=[SecurityRule(id=f"r{i}",name=f"r{i}",position=i+1,sources=[f"a{i}"],destinations=[f"g{i%100}"],services=["any"],action="allow") for i in range(1000)])
    report,graph=AnalysisEngine().analyze(cfg)
    assert len(graph)>2000 and not report.analyzer_warnings