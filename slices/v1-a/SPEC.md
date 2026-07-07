# SPEC — v1-a: vitest + per-scanner fixture tests

**Branch:** `pod/v1a-scanner-tests`  
**Depends:** —

## Goal

Add `vitest` and at least one direct-import test per scanner using `test-data/` fixtures. `npm test` must exit 0.

## Scope

- Add `vitest` devDependency; `"test": "vitest run"` in package.json
- `tests/scanners/*.test.ts` — import scanner functions from `src/scanners/*`, not CLI shell-out
- Minimum coverage (from `plan/VIBESAFE-AUDIT.md` matrix):

| Test file | Scanner | Fixtures | Assert |
|-----------|---------|----------|--------|
| `secrets.test.ts` | secrets | `aws-secrets-tests.txt` | ≥1 High AWS finding |
| `secrets.test.ts` | secrets | `safe-file.txt` | 0 High findings |
| `configuration.test.ts` | configuration | `app.config.json` | CORS High + DEBUG Medium |
| `endpoints.test.ts` | endpoints | `endpoint-test.js` | `/admin` Medium+ |
| `uploads.test.ts` | uploads | `multer-test.js` | missing limits (needs hasBackend=true) |
| `logging.test.ts` | logging | `logging-test.js` | ≥1 PII finding |
| `httpClient.test.ts` | httpClient | `http-client-unsafe.js` | ≥1 missing timeout |
| `rateLimiting.test.ts` | rateLimiting | `rate-limit-missing.js` vs present | advisory only when missing |
| `dependencies.test.ts` | dependencies | `vulnerable-deps/package.json` | vulns found (mock OSV or live with timeout) |

- `vitest.config.ts` — resolve `src/` imports; include `tests/**/*.test.ts`
- Commit on branch `pod/v1a-scanner-tests`

## Out of scope

- Fixing scanner bugs (v1-h)
- CI workflow changes (v1-c)
- CVE severity mapping fixes (v1-f) — tests may assert vulns.length > 0 without severity yet

## Done when

`bash slices/v1-a/verify.sh` exits 0.
