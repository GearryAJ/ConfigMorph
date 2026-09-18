# Realistic fixture testing

Phase N uses deterministic, synthetic ASA 9.20 and FortiOS 7.4 configurations. No fixture may contain customer, organization, public-address, credential, or device data. Each generated header records `synthetic = true`, source vendor, source version, and intended coverage.

## Tiers

| Tier | Objects | Services | Policies |
|---|---:|---:|---:|
| SMALL | 20 | 10 | 10 |
| MEDIUM | 250 | 100 | 250 |
| LARGE | 1,000 | 500 | 1,000 |

`tests/realistic_fixtures.py` covers interfaces, VLANs/zones, objects, nested groups, services, ordered policies, disabled entries, routes, unresolved and unused objects, name collisions, NAT/VIP review input, and explicit unsupported syntax. `tests/test_realistic_regression.py` compares semantic models after excluding `generated_at`; failures identify vendor, tier, stage, and invariant. Malformed cases cover truncation, invalid masks, malformed quoting, unknown commands, missing references, and unfinished groups.

## Commands

```text
pytest -q tests/test_realistic_regression.py
python tools/benchmark_realistic.py
python -m pip install -e ".[test,browser]"
python -m playwright install chromium
pytest -q tests/browser
```

Goldens are semantic assertions, not raw snapshots. Update generators only with synthetic RFC1918 data. Review normalized entity counts, unsupported accounting, policy order, NAT absence from candidate commands, and ZIP allowlist before accepting an intentional change. Never update expected behavior merely to clear a failure.

The optional browser job currently records the malformed-input check as passing. The happy path is an explicit expected failure because the vendored HTMX asset does not initialize under the current CSP in Chromium. API-level workflow coverage remains mandatory; do not make the optional browser job required until that infrastructure issue is resolved.