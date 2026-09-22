# Vendor documentation policy

Migration semantics require official source-vendor documentation, official target-vendor documentation, implemented behavior, and tests. Accepted sources: official CLI references, administration/configuration guides, release notes, feature documentation, and compatibility guides on `cisco.com`, `docs.fortinet.com`, or `docs.paloaltonetworks.com`.

Blogs, community forums, Reddit, Stack Overflow, third-party migration guides, and generated explanations cannot establish semantics. References store metadata and official URLs only. Runtime never fetches documentation. Missing authoritative evidence is `VERSION_NOT_VERIFIED` or `MANUAL_REVIEW`; it is never inferred from feature presence or another release.

Generic API action documentation does not establish a product configuration tree. When official guidance delegates XPath or XML discovery to a device API Browser or debug output, version-matched device evidence is required before enabling mutation. CLI syntax must not be converted to XML API requests by token splitting or path heuristics.

Device captures use confidence states `DEVICE_CAPTURED`, `DOCS_ONLY`, `INFERRED`, and `UNVERIFIED`. Mutation mappings require reviewed `DEVICE_CAPTURED` evidence from the matching OS profile and management mode. Raw captures remain ignored; only sanitized, metadata-free derived fixtures may enter Git after manual review.