# Analysis semantics

Phase D analyzes only `FirewallConfig`; source syntax is never read by the graph or analyzers. The NetworkX `MultiDiGraph` stays internal. API clients receive Pydantic DTOs with stable per-configuration node IDs (`<type>:<IR id>`).

## Graph

Node types: configuration, interface, zone, address, address group, service, service group, security policy, NAT policy, static route, VPN, unknown reference.

Edges point from the referencing object to its dependency. Types: `MEMBER_OF`, `USES_SOURCE`, `USES_DESTINATION`, `USES_SERVICE`, `FROM_ZONE`, `TO_ZONE`, `USES_INTERFACE`, `NAT_ORIGINAL_SOURCE`, `NAT_ORIGINAL_DESTINATION`, `NAT_TRANSLATED_SOURCE`, `NAT_TRANSLATED_DESTINATION`, `ROUTE_INTERFACE`, `ROUTE_NEXT_HOP`, `REFERENCES`. Parallel edges preserve different semantics between the same nodes.

Forward, reverse, recursive, shortest-path, and reference queries are cycle-safe NetworkX operations. Group cycles produce `GROUP_CYCLE` findings.

## Findings

- **Unresolved**: a normalized reference has no matching object of the expected domain. Literal `any`, IP route next hops, and interface NAT markers are not object references.
- **Unused object**: an address or service has no transitive reverse path to a security policy, NAT policy, or static route. Membership in a group used by an operational object makes the member used.
- **Orphan group**: a group has valid members but no transitive operational reverse reference. Its members remain separate objects and are not labeled orphan groups.
- **Empty group**: zero valid members. Evidence includes declared, valid, and missing members.
- **Duplicate object**: normalized address type/value, normalized service protocol/ports, or normalized group member set is equal. Names are irrelevant.
- **Duplicate policy**: source/destination zones, source/destination addresses, services, and action are equal after order normalization. Name and description are ignored; positions remain evidence.
- **Broad rule**: source, destination, or service contains `any`/`all`; source plus destination produces `ANY_ANY_RULE`. This means “Broad rule — review recommended,” not vulnerability.
- **Disabled rule**: disabled security rule. NAT is not reported because the current IR has no NAT enabled field.

## Potential shadowing

Potential shadowing is advisory and requires engineer review. The analyzer compares enabled rules with the same normalized action. An earlier rule must deterministically contain every later match dimension. Deterministic containment means exact references, `any`, or same-family IPv4/IPv6 network containment via `ipaddress`. FQDNs, dynamic groups, users, application IDs, profiles, and unresolved semantic expansion are never guessed. False-positive avoidance takes priority over coverage.

Rules are indexed by action before ordered comparison. This avoids comparing unrelated action sets; worst-case matching within one action bucket remains quadratic. Typical exact-rule checks short-circuit early.

## Impact

Impact follows explicit reverse graph references. `LOW` means no references. `MEDIUM` means references exist only through groups or other non-policy objects. `HIGH` means a security or NAT policy references the object directly or transitively. This is reference scope, not business-risk scoring. Results include direct/recursive counts, typed policy/group/route lists, and useful shortest dependency chains.

Analyzer failures are isolated and listed in `analyzer_warnings`; recoverable failure does not discard other findings.