# Changelog

All notable changes follow [Keep a Changelog](https://keepachangelog.com/en/1.1.0/). This project uses [Semantic Versioning](https://semver.org/).

## [Unreleased]

### Changed

- Fixed Phase N.1 benchmark entrypoint imports and corrected browser smoke expectations for the CSP-compatible local form adapter. Migration scope is unchanged.
- Added Phase N synthetic SMALL/MEDIUM/LARGE ASA and FortiOS fixture regression, deterministic semantic comparisons, malformed-input recovery checks, stage benchmarks, and optional offline Playwright smoke coverage. Migration scope is unchanged.
- Added official-vendor documentation provenance, explicit OS version profiles, conservative capability checks, version validation, and review/export provenance for ASA/FortiOS to PAN-OS migration.
- Downgraded previously optimistic migration claims where source or target version documentation and tested syntax evidence are incomplete.
- Expanded focused official references; added structured evidence completeness, PAN command provenance/context, orphan-reference validation, and development-time documentation coverage reporting.
- Closed emitted object, service, security-policy, and static-route evidence for ASA 9.20/9.22/9.24 and FortiOS 7.4/7.6 to PAN-OS 11.1; manual-review capabilities remain outside the release gate.
- Corrected PAN-OS 11.1 local command roots, separated management context from CLI tokens, constrained serializer tokens, and retained NAT, Panorama, and PAN-OS 12.1 route blocks.
- Added explicit security-rule placement and a documented, deterministic Configuration API move intent artifact; candidate set files remain set commands only.
- Hardened the local import-to-export workflow, explicit PAN-OS 11.1 target selection, accessible file drop/picker controls, release package allowlist, and release-level source integration coverage.
- Split NAT evidence into source/destination subtypes. Added zero-optimism evidence dimensions and explicit review-only accounting; no NAT candidate generation was restored.
- Documented PAN-OS 11.1 DIPP, interface-address PAT, one-to-one DNAT, original-destination route lookup, and post-NAT security-zone semantics without enabling NAT generation.

### Added

- Closed PAN-OS 11.1 named candidate snapshot and restore evidence; added explicit cleanup confidence, lifecycle error states, pre-existing candidate preservation tests, isolated-lab acknowledgement, and commit/deployment request denial. Live transport remains blocked pending verified XML mutation mapping and snapshot cleanup.
- Added disabled-by-default PAN-OS 11.1 lab-validation orchestration, sanitized reports, fake transport coverage, UI status, and export support. Live transport remains blocked pending authoritative candidate-restore evidence.
- FortiGate → PAN-OS alpha candidate migration through the normalized IR, shared planner, renderer, review, and validation workflow.
- Central migration-pair registry and source adapters for Cisco ASA and FortiGate.
- FortiGate address, group, service, policy, interface PAT, narrow VIP DNAT, and static-route fixtures.
- Cross-vendor parity, migration accounting, API, architecture, and 1,000-object/1,000-policy performance coverage.

### Changed

- Prepared development version `0.2.0-alpha.1`; no release or tag created.
- Migration API responses now identify source and target vendors; unsupported pairs are rejected centrally.

### Security

- FortiGate migration remains local-only and candidate-only. Central NAT, VDOM, SD-WAN, security profiles, IP pools, and incomplete VIP semantics remain explicit review items.

## [0.1.0-alpha.1] - 2026-09-16

### Added

- Local Cisco ASA, FortiGate, and PAN-OS XML parsing into a vendor-neutral IR.
- Dependency visualization, configuration analysis, impact analysis, and potential-shadowing findings.
- Cisco ASA → PAN-OS compatibility planning and candidate set-command generation.
- Semantic review decisions, hash invalidation, validation, traceability, and guarded review ZIP export.
- SQLite persistence, FastAPI/Jinja UI, local vendored browser assets, Docker Compose workflow, and synthetic tests.

### Security

- Local-only processing, loopback Compose bind, input limits, hardened XML parsing, security headers, and no telemetry/external AI APIs.

[Unreleased]: https://github.com/Nandi-Pura/Convert-In/compare/v0.1.0-alpha.1...HEAD
[0.1.0-alpha.1]: https://github.com/Nandi-Pura/Convert-In/releases/tag/v0.1.0-alpha.1