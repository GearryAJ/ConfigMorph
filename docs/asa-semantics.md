# Cisco ASA normalized semantics

## ACL attachment and topology

`access-group ACL in|out interface NAMEIF` attaches every normalized rule from that ACL. Rules preserve ACL name, direction, interface, source line, explicit ASA line number, remarks, and active/unattached state. Inbound rules use the attached `nameif` as ingress context. Outbound ACLs remain `MANUAL_REVIEW`.

Destination topology uses configured state only: directly connected interface networks plus static routes. `ipaddress` longest-prefix match selects the most specific route, then the lowest administrative distance represented in the IR. Equal-prefix/equal-distance routes to different contexts are `AMBIGUOUS`. Dynamic routing is not calculated. Evidence records the matched prefix, route kind, and context.

Address groups expand recursively with a cache and cycle guard. One resulting context is resolved; multiple contexts are `MULTIPLE`. `any`, ranges spanning routes, FQDNs, missing objects, and cycles are not guessed. DNS and live firewall access are never used.

## Services

TCP, UDP, ICMP, IP, and mixed service-group protocols remain distinct. Source and destination ports remain separate. `eq` and `range` normalize exactly. `lt`, `gt`, and `neq` remain operator metadata and force review. Named ports are intentionally bounded: `www/http=80`, `https=443`, `ssh=22`, `domain=53`, `smtp=25`. Unknown names warn and remain unrendered. ICMP/IP policies remain review-only where PAN service semantics are not exact.

## NAT

Modern object NAT preserves ingress/egress context, original/translated source, deterministic name, and section 2 ordering. Static source NAT and dynamic interface PAT can render only with complete references and confirmed zone mappings. Interface PAT uses explicit `INTERFACE_ADDRESS`; no address is invented.

Manual/twice NAT preserves source, destination, service translation tuples and interfaces. Default manual NAT is section 1; `after-auto` is section 3. Identity NAT is detected. Identity, twice, after-auto, incomplete, and ambiguous NAT remain `MANUAL_REVIEW` and emit no candidate command.

Known limits: IPv4 route resolution only; no dynamic routing, VPN-derived topology, policy routing, DNS, identity/twice NAT rendering, or automatic outbound ACL conversion.