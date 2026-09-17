# Migration

## Architecture

`vendor parser → FirewallConfig IR → compatibility/planner → confirmed mappings → PAN command DTOs → serializer → candidate/report`

Migration code consumes normalized IR only. It does not parse ASA source syntax. Every normalized entity receives one `EXACT`, `SUPPORTED`, `PARTIAL`, `MANUAL_REVIEW`, or `UNSUPPORTED` compatibility record. Omitted entities therefore remain visible in the report.

## ASA to PAN-OS scope

The PAN-OS renderer emits deterministic set commands for validated host/network/range/FQDN addresses, static address groups, normalized TCP/UDP destination-port services, static service groups, security rules with explicit mapped zones, and simple static routes. It preserves policy order, disabled state, allow/deny, descriptions, `log-start`, and `log-end`. PAN built-ins `any`, `application-default`, `service-http`, and `service-https` are reused.

ASA `access-group` attachment, direction, ACL order/remarks, source-port constraints, and protocol fidelity are retained. Inbound ingress context comes from the attachment. Destination context is derived only by connected/static-route longest-prefix matching; evidence appears in compatibility output. Unattached, outbound, any-destination, multi-zone, unresolved, and ambiguous policies remain review-only. Interfaces are mapping-only. Zone creation is not automatic.

NAT remains conservative. Modern object static source NAT and dynamic interface PAT emit candidate rules only with complete semantics and confirmed context mappings. Manual/twice NAT translation tuples, identity status, and sections 1/2/3 are preserved but not rendered. Destination/twice/identity/advanced NAT, VPN, dynamic routing, App-ID inference, User-ID, profiles, inspection, HA, multi-context, policy routing, QoS, and time-range semantics are not automatically converted.

## Mapping and naming

Workspace-local `migration/mappings.json` stores target mode, `vsys` (default `vsys1`), device group, virtual router, and interface/zone mappings. Suggested zones are separate from `confirmed`; suggestions never authorize generation. Routes accept a confirmed mapping by physical ASA interface or `nameif`.

Names deterministically replace unsupported punctuation with `_`, preserve Unicode word characters, cap candidates at 63 characters, and add `_2`, `_3`, etc. on case-insensitive collisions. Reports retain source/target names, reason, and collision status. Values containing whitespace, quotes, or backslashes are PAN-OS quoted and escaped; control characters are blocked.

## Validation and review

Generation validates the structured plan plus the emitted subset: recognized context, IP/netmask values, and port syntax. This is application-level syntax validation, **not validation by PAN-OS**. Critical parse errors block all candidate output. Unresolved references and group cycles block affected entities. Potential shadowing remains advisory; policy order is never changed.

Generated files are always **Candidate Configuration — Engineer Review Required**:

- `migration/candidate-pan-os.set`
- `migration/migration-report.json`
- `migration/compatibility.json`
- `migration/mappings.json`

Review all manual-review/unsupported findings, mappings, normalized parser warnings, names, command references, topology, and behavior on an isolated PAN-OS lab system before any separate deployment process. This application has no deployment capability.

The Phase H semantic review queue, persisted engineer decisions, stale-decision invalidation, staged validation, and final package are documented in [review.md](review.md). Final package export is blocked by validation failures; candidate inspection remains available.