# Semantic Migration Review

Phase H adds a local engineer-review gate after ASA-to-PAN candidate generation. It does not deploy, connect to PAN-OS, or certify production safety.

## Workflow

1. Analyze an ASA configuration and confirm interface/zone mappings.
2. Generate the PAN-OS candidate.
3. Review every normalized entity in **Migration Readiness → Semantic Review**. Compare source intent with target intent, inspect preserved/changed/dropped fields, findings, dependencies, and generated commands.
4. Record a local note and choose `NOT_REVIEWED`, `REVIEWED`, `ACCEPTED`, `NEEDS_CHANGES`, or `BLOCKED`.
5. Run staged validation. Resolve every `BLOCKING` finding.
6. Export the final review package. Validate the candidate separately on an isolated PAN-OS lab system before any deployment process.

`ACCEPTED` means only that an engineer reviewed that item. It does not mean production ready, device validated, or safe to deploy. `MANUAL_REVIEW` and `UNSUPPORTED` are compatibility outcomes, not engineer decisions; such entities remain visible even when no command was generated.

## Persistence and invalidation

Workspace-local `migration/review.json` contains only entity IDs, decisions, notes, and semantic hashes. Regeneration compares canonical target intent plus generated commands. A changed hash resets only that entity to `NOT_REVIEWED`; unchanged decisions survive. Source configuration is not copied into review state.

## Validation

Validation checks normalized IR, mappings, generated command structure, references, review accounting, and traceability. Results are `PASS`, `WARNING`, or `BLOCKING`. Blocking findings prevent final ZIP export but do not hide the candidate or compatibility evidence. Validation is application-level only; PAN-OS does not validate the output.

## Final package

`migration-review-package.zip` contains:

- `candidate-pan-os.set`
- `migration-report.json`
- `review-report.json`
- `validation-report.json`
- `mappings.json`
- `security-rule-ordering.json` when security rules are generated
- `README`

`source.cfg` is deliberately excluded. All processing and persistence remain local. Workspace files still contain sensitive plaintext and require normal filesystem protection.