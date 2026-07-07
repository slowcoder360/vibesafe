# SPEC — v1-c: CI fixtures + honest build

**Branch:** `pod/v1c-ci-fixtures`  
**Depends:** v1-a (merge pod/v1h-scanner-fixes + pod/v1f-cve-severity into base)

## Goal

CI proves tests pass and scans `test-data/` using **local** `dist/index.js`, not registry `npx vibesafe`.

## Scope

1. Base branch: merge `pod/v1h-scanner-fixes` and `pod/v1f-cve-severity` (or rebase onto v1h then cherry-pick v1f)
2. `.github/workflows/ci.yml`:
   - `npm ci && npm run build && npm test`
   - `node dist/index.js scan test-data/ --high-only` (expect exit 1 — fixtures have highs)
   - Remove `npx vibesafe scan`
3. Document in workflow comment why exit 1 is expected OR add `--no-fail` if v1-i lands first (skip v1-i for now; allow failure exit 1 with `continue-on-error: false` only for test step)

## Done when

`bash slices/v1-c/verify.sh` exits 0.
