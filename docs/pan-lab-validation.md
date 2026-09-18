# PAN-OS lab validation

Optional validation targets an isolated `LOCAL_FIREWALL` running PAN-OS 11.1. It never commits, deploys, handles NAT, targets Panorama, or accepts credentials through the web UI.

## Current safety state

`FCS_PAN_LAB_VALIDATION_ENABLED` defaults to `false`. Enabling it does not open a network connection. The endpoint returns `VERSION_NOT_VERIFIED` because official evidence found for `validate full` and candidate set commands did not establish the exact snapshot restoration operation required by this project's cleanup invariant. No live transport is implemented until that evidence is recorded.

The transport-neutral orchestrator is covered with fake-transport tests. Its required sequence is version check, snapshot, apply generated commands, `validate full`, restore, verify restoration. Any failed restoration becomes `BLOCKING`. `commit_performed` is always `false` and model validation rejects any contrary report.

## Configuration boundary

- `FCS_PAN_LAB_VALIDATION_ENABLED=true`: exposes the blocked opt-in state only.
- `FCS_PAN_LAB_HOST`: reserved; never persisted or returned.
- `FCS_PAN_LAB_HOST_ALLOWLIST`: reserved for exact host allowlisting.
- `FCS_PAN_LAB_CA_BUNDLE`: reserved for trusted TLS certificate verification.

API keys, passwords, private keys, and insecure TLS switches are intentionally absent. Reports contain status, candidate SHA-256, timing, sanitized device categories/messages, provenance IDs, restoration state, and documentation references. Reports contain no host, username, credential, source configuration, or candidate text.

## Official PAN-OS 11.1 references

- `PANOS-11.1-CLI-VALIDATE`: [Commit Configuration Changes](https://docs.paloaltonetworks.com/pan-os/11-1/pan-os-cli-quick-start/use-the-cli/commit-configuration-changes). `validate full` enqueues syntactic and semantic validation; commit is separate.
- `PANOS-11.1-CLI-LOAD-TEXT`: [Load Configuration Settings from a Text File](https://docs.paloaltonetworks.com/pan-os/11-1/pan-os-cli-quick-start/use-the-cli/load-configurations). Documents candidate set-command loading.
- `PANOS-11.1-XML-API-ACTIONS`: [PAN-OS XML API Request Types and Actions](https://docs.paloaltonetworks.com/pan-os/11-1/pan-os-panorama-api/pan-os-xml-api-request-types/commit-configuration-api). Documents candidate configuration actions and operational validation category.

Live activation requires authoritative PAN-OS 11.1 snapshot, restore, deletion, and restoration-verification syntax; a TLS-verifying, allowlisted adapter; an isolated lab account with no commit privilege; explicit `pan_lab` tests.