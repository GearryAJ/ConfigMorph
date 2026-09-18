# Realistic fixture performance

Measured 2026-09-18 on Windows, Python 3.12.10. Values are visibility baselines, not product claims. Peak memory uses `tracemalloc`; platform variation does not fail CI.

| Fixture | Parse | Normalize | Analyze | Plan | Render | Total | Peak MiB |
|---|---:|---:|---:|---:|---:|---:|---:|
| ASA SMALL | 0.018 | 0.003 | 0.022 | 0.022 | 0.003 | 0.068 | 0.6 |
| ASA MEDIUM | 0.076 | 0.004 | 0.198 | 0.289 | 0.027 | 0.593 | 5.8 |
| ASA LARGE | 0.508 | 0.036 | 1.707 | 2.080 | 0.125 | 4.456 | 23.1 |
| FortiOS SMALL | 0.037 | 0.001 | 0.013 | 0.024 | 0.011 | 0.085 | 0.5 |
| FortiOS MEDIUM | 0.504 | 0.004 | 0.214 | 0.330 | 0.148 | 1.200 | 7.3 |
| FortiOS LARGE | 1.726 | 0.015 | 1.165 | 1.798 | 0.598 | 5.302 | 28.4 |

The benchmark enforces a loose 30-second total ceiling per fixture. Re-measure on representative hardware before changing it. Memory remains informational.