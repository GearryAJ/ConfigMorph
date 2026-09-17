import networkx as nx
from app.core.models import FirewallConfig
from .models import EdgeType, GraphDTO, GraphEdge, GraphNode, NodeType

class DependencyGraphBuilder:
    def build(self, cfg: FirewallConfig) -> nx.MultiDiGraph:
        g=nx.MultiDiGraph(); self._node(g,"configuration","Configuration",NodeType.CONFIGURATION)
        collections=((cfg.interfaces,NodeType.INTERFACE),(cfg.zones,NodeType.ZONE),(cfg.addresses,NodeType.ADDRESS),(cfg.address_groups,NodeType.ADDRESS_GROUP),(cfg.services,NodeType.SERVICE),(cfg.service_groups,NodeType.SERVICE_GROUP),(cfg.security_policies,NodeType.SECURITY_POLICY),(cfg.nat_policies,NodeType.NAT_POLICY),(cfg.static_routes,NodeType.STATIC_ROUTE),(cfg.vpn_objects,NodeType.VPN))
        lookup={}
        for items,kind in collections:
            for item in items:
                key=self._node(g,item.id,item.name,kind); lookup.setdefault(item.id,key); lookup.setdefault(item.name,key)
        def ref(source,name,edge,kind):
            if not name or name.lower() in {"any","any4","any6","all","interface"}: return
            target=lookup.get(name)
            if target is None:
                target=f"unknown_reference:{kind}:{name}"
                if target not in g: g.add_node(target,dto=GraphNode(id=target,object_id=name,name=name,type=NodeType.UNKNOWN_REFERENCE,unknown_kind=kind))
            g.add_edge(source,target,type=edge.value)
        for group,kind in [(x,"address") for x in cfg.address_groups]+[(x,"service") for x in cfg.service_groups]:
            source=lookup[group.id]
            for member in group.members: ref(source,member,EdgeType.MEMBER_OF,kind)
        for zone in cfg.zones:
            for interface in zone.interfaces: ref(lookup[zone.id],interface,EdgeType.USES_INTERFACE,"interface")
        for interface in cfg.interfaces:
            if interface.zone: ref(lookup[interface.id],interface.zone,EdgeType.REFERENCES,"zone")
        for rule in cfg.security_policies:
            source=lookup[rule.id]
            for values,edge,kind in ((rule.source_zones,EdgeType.FROM_ZONE,"zone"),(rule.destination_zones,EdgeType.TO_ZONE,"zone"),(rule.sources,EdgeType.USES_SOURCE,"address"),(rule.destinations,EdgeType.USES_DESTINATION,"address"),(rule.services,EdgeType.USES_SERVICE,"service")):
                for value in values: ref(source,value,edge,kind)
        for rule in cfg.nat_policies:
            source=lookup[rule.id]
            for values,edge in ((rule.original_source,EdgeType.NAT_ORIGINAL_SOURCE),(rule.original_destination,EdgeType.NAT_ORIGINAL_DESTINATION),(rule.translated_source,EdgeType.NAT_TRANSLATED_SOURCE),(rule.translated_destination,EdgeType.NAT_TRANSLATED_DESTINATION)):
                for value in values: ref(source,value,edge,"address")
        for route in cfg.static_routes:
            source=lookup[route.id]
            if route.interface: ref(source,route.interface,EdgeType.ROUTE_INTERFACE,"interface")
            if route.next_hop in lookup: ref(source,route.next_hop,EdgeType.ROUTE_NEXT_HOP,"address")
        return g
    @staticmethod
    def _node(g,object_id,name,kind):
        key=f"{kind.value}:{object_id}"; g.add_node(key,dto=GraphNode(id=key,object_id=object_id,name=name,type=kind)); return key

def serialize_graph(g:nx.MultiDiGraph)->GraphDTO:
    return GraphDTO(nodes=[d["dto"] for _,d in g.nodes(data=True)],edges=[GraphEdge(source=a,target=b,type=d["type"]) for a,b,d in g.edges(data=True)])