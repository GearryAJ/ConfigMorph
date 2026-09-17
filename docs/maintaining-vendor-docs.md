# Maintaining vendor documentation

1. Locate official vendor documentation.
2. Identify the exact OS family.
3. Add a unique reference in `docs/vendor-reference/`.
4. Associate the capability with that reference and profile.
5. Add a synthetic fixture and expected semantics.
6. Add an explicit version test.
7. Update `docs/support-matrix.md`.
8. Run all CI checks.

Do not copy manuals into the repository. If authoritative evidence is unavailable, record the capability as not verified.