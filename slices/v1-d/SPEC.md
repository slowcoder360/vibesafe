# SPEC — v1-d: AI suggestions opt-in

**Branch:** `pod/v1d-ai-opt-in`  
**Depends:** v1-b

## Goal

`-r/--report` produces deterministic markdown without LLM. `--ai-suggestions` required for OpenAI calls.

## Scope

1. Base: `pod/v1b-version-cleanup`; merge vitest from v1-a only if needed for tests (optional: add minimal test for report path)
2. `src/index.ts`: add `--ai-suggestions` flag to scan command
3. `src/reporting/markdown.ts`: call `generateAISuggestions` only when flag set
4. Do not load/use OpenAI when flag absent (lazy import ok)
5. Update README report section
6. Add `tests/reporting/markdown.test.ts` or CLI test: `-r` without flag does not call OpenAI (mock/spy)

## Done when

`bash slices/v1-d/verify.sh` exits 0.
