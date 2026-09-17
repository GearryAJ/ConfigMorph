from enum import StrEnum
from pydantic import BaseModel, Field

class NodeType(StrEnum):
    CONFIGURATION="configuration"; INTERFACE="interface"; ZONE="zone"; ADDRESS="address"; ADDRESS_GROUP="address_group"; SERVICE="service"; SERVICE_GROUP="service_group"; SECURITY_POLICY="security_policy"; NAT_POLICY="nat_policy"; STATIC_ROUTE="static_route"; VPN="vpn"; UNKNOWN_REFERENCE="unknown_reference"

class EdgeType(StrEnum):
    MEMBER_OF="MEMBER_OF"; USES_SOURCE="USES_SOURCE"; USES_DESTINATION="USES_DESTINATION"; USES_SERVICE="USES_SERVICE"; FROM_ZONE="FROM_ZONE"; TO_ZONE="TO_ZONE"; USES_INTERFACE="USES_INTERFACE"; NAT_ORIGINAL_SOURCE="NAT_ORIGINAL_SOURCE"; NAT_ORIGINAL_DESTINATION="NAT_ORIGINAL_DESTINATION"; NAT_TRANSLATED_SOURCE="NAT_TRANSLATED_SOURCE"; NAT_TRANSLATED_DESTINATION="NAT_TRANSLATED_DESTINATION"; ROUTE_INTERFACE="ROUTE_INTERFACE"; ROUTE_NEXT_HOP="ROUTE_NEXT_HOP"; REFERENCES="REFERENCES"

class GraphNode(BaseModel):
    id: str; object_id: str; name: str; type: NodeType; unknown_kind: str|None=None
class GraphEdge(BaseModel):
    source: str; target: str; type: EdgeType
class GraphDTO(BaseModel):
    nodes: list[GraphNode]=Field(default_factory=list); edges: list[GraphEdge]=Field(default_factory=list)
class GraphSummary(BaseModel):
    objects: int; policies: int; edges: int; nodes_by_type: dict[str,int]
    graph: GraphDTO
class GraphScope(BaseModel):
    root: GraphNode; mode: str; depth: int; truncated: bool; total_candidates: int
    graph: GraphDTO