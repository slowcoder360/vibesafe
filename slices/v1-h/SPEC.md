# SPEC — v1-h: scanner correctness bundle

**Branch:** `pod/v1h-scanner-fixes`  
**Depends:** v1-a

## Goal

Fix four audit-documented scanner bugs; extend tests to lock behavior.

## Scope

1. **express-fileupload** (`uploads.ts`): match `fileUpload()` from `express-fileupload` import, not only `expressUpload()`
2. **rate-limit import** (`rateLimiting.ts`): detect `require('express-rate-limit')` / import in source, not only package.json — `rate-limit-present.js` should NOT trigger advisory when scanned with express in deps context
3. **Next.js paths** (`endpoints.ts`): resolve `/api/admin` not `/pages/api/admin`
4. **superagent chain** (`httpClient.ts`): if `.timeout(` appears on same member-expression chain, do not flag missing timeout
5. Add/update tests in `tests/scanners/` for each fix using existing test-data fixtures
6. `npm test` green

## Out of scope

- New scanner categories
- Logging PII keyword tuning (defer)

## Done when

`bash slices/v1-h/verify.sh` exits 0.
