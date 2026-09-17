from app.core.models import Vendor
from app.core.parsing import parse_config
from app.core.migration import InterfaceMapping,MigrationMappings,MigrationPlanner
from app.core.renderers import PaloAltoRenderer
from app.vendors.cisco_asa.topology import AsaTopologyResolver,TopologyStatus

BASE='''interface Gi0/0\n nameif outside\n ip address 192.0.2.2 255.255.255.0\n!\ninterface Gi0/1\n nameif inside\n ip address 10.0.0.1 255.255.255.0\n!\ninterface Gi0/2\n nameif dmz\n ip address 10.20.30.1 255.255.255.0\n!\n'''
MAP=MigrationMappings(interfaces=[InterfaceMapping(source_interface=f'Gi0/{i}',source_nameif=s,target_interface=f'ethernet1/{i+1}',target_zone=t,confirmed=True) for i,(s,t) in enumerate([('outside','untrust'),('inside','trust'),('dmz','dmz')])])

def test_attachment_connected_topology_policy_and_named_service():
    cfg=parse_config(BASE+'''object network WEB\n host 10.20.30.10\naccess-list OUT line 10 remark publish web\naccess-list OUT line 10 extended permit tcp any object WEB eq https\naccess-group OUT in interface outside\n''',Vendor.ASA)
    rule=cfg.security_policies[0]
    assert rule.source_zones==['outside'] and rule.destination_zones==['dmz'] and rule.description=='publish web'
    assert rule.position==10 and cfg.services[-1].protocol=='tcp' and cfg.services[-1].destination_ports==['443']
    plan=MigrationPlanner().plan(cfg,MAP); lines,_=PaloAltoRenderer().render(plan)
    assert next(x for x in plan.compatibility if x.entity_id==rule.id).status=='MANUAL_REVIEW'
    assert not lines

def test_longest_prefix_groups_any_outbound_and_unattached():
    cfg=parse_config(BASE+'''route outside 0.0.0.0 0.0.0.0 192.0.2.1\nroute dmz 172.16.0.0 255.255.0.0 10.20.30.2\nobject network A\n host 172.16.2.3\nobject network B\n host 8.8.8.8\nobject-group network MIX\n network-object object A\n network-object object B\naccess-list X extended permit ip any object A\naccess-list Y extended permit ip any object-group MIX\naccess-list Z extended permit ip any any\naccess-group X in interface inside\naccess-group Y in interface inside\n''',Vendor.ASA)
    resolver=AsaTopologyResolver(cfg)
    assert resolver.resolve(['A']).zones==['dmz']
    assert resolver.resolve(['MIX']).status==TopologyStatus.MULTIPLE
    assert resolver.resolve(['any']).status==TopologyStatus.AMBIGUOUS
    statuses={x.source_name:x.status for x in MigrationPlanner().plan(cfg,MAP).compatibility if x.entity_type=='security_policy'}
    assert statuses['X line 22']=='MANUAL_REVIEW'  # ICMP/IP target service remains intentionally blocked.
    assert statuses['Y line 23']=='MANUAL_REVIEW' and statuses['Z line 24']=='MANUAL_REVIEW'

def test_service_source_port_operators_and_groups():
    cfg=parse_config('''object service WEB\n service tcp source eq 1024 destination range 8000 8080\nobject-group service DNS udp\n port-object eq domain\nobject-group service MIX\n service-object tcp destination eq https\n service-object udp destination eq domain\n''',Vendor.ASA)
    assert cfg.services[0].source_ports==['1024'] and cfg.services[0].destination_ports==['8000-8080']
    assert cfg.service_groups[0].members==[] and cfg.service_groups[0].destination_ports==['53']
    assert {cfg.services[-2].protocol,cfg.services[-1].protocol}=={'tcp','udp'}

def test_nat_taxonomy_order_and_safe_rendering():
    cfg=parse_config(BASE+'''object network LAN\n subnet 10.0.0.0 255.255.255.0\n nat (inside,outside) dynamic interface\nobject network WEB\n host 10.20.30.10\n nat (dmz,outside) static 192.0.2.10\nnat (inside,outside) source static LAN LAN destination static WEB WEB\nnat (inside,outside) after-auto source dynamic LAN interface\n''',Vendor.ASA)
    assert [x.vendor_extensions['section'] for x in cfg.nat_policies]==[2,2,1,3]
    assert [x.type for x in cfg.nat_policies]==['dynamic_pat','static_source_nat','identity_nat','twice_nat']
    plan=MigrationPlanner().plan(cfg,MAP); lines,_=PaloAltoRenderer().render(plan)
    assert sum(x.entity_type=='nat_policy' and x.status=='SUPPORTED' for x in plan.compatibility)==0
    assert not lines
    assert not any('NAT-003' in x or 'NAT-004' in x for x in lines)

def test_equal_prefix_route_is_ambiguous_and_group_cycle_safe():
    cfg=parse_config(BASE+'''route outside 203.0.113.0 255.255.255.0 192.0.2.1 1\nroute dmz 203.0.113.0 255.255.255.0 10.20.30.2 1\nobject network D\n host 203.0.113.9\nobject-group network A\n network-object object B\nobject-group network B\n network-object object A\n''',Vendor.ASA)
    resolver=AsaTopologyResolver(cfg)
    assert resolver.resolve(['D']).status==TopologyStatus.AMBIGUOUS
    assert resolver.resolve(['A']).status==TopologyStatus.UNRESOLVED