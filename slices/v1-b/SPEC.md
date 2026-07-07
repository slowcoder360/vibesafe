# SPEC — v1-b: version sync + reporting cleanup

**Branch:** `pod/v1b-version-cleanup`  
**Depends:** —

## Goal

Single source of truth for CLI version; remove stale `src/reporting/*.js` duplicates; address dev `npm audit` highs where safe.

## Scope

1. `src/index.ts` — `program.version()` reads from `package.json` (import or readFileSync), not hardcoded `0.0.1`
2. Delete `src/reporting/markdown.js` and `src/reporting/aiSuggestions.js` if superseded by `.ts` (confirm not referenced)
3. Run `npm audit fix` for dev dependency vulns where non-breaking
4. `npm run build` clean

## Out of scope

- vitest / tests (v1-a)
- AI opt-in (v1-d)
- Changing publish `"files"` array

## Done when

`bash slices/v1-b/verify.sh` exits 0.
