# SPEC — v1-f: CVE severity fallback

**Branch:** `pod/v1f-cve-severity`  
**Depends:** v1-a

## Goal

When OSV returns vulnerabilities without CVSS v3, assign non-None severity so `--high-only` and reporting surface real dep risk.

## Scope

- `src/scanners/dependencies.ts` — fallback when `getHighestCvssScore` returns 0 but `vulns.length > 0`:
  - Use OSV ecosystem severity if present, else default `Medium` (document in code comment)
- Update `tests/scanners/dependencies.test.ts` to assert `maxSeverity !== 'None'` for `test-data/vulnerable-deps/` lodash or axios
- `npm test` green

## Out of scope

- Lockfile parsing (v1-e)
- Multi-manifest (v1-g)

## Done when

`bash slices/v1-f/verify.sh` exits 0.
