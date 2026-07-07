# HANDOFF — V1 foundation hardening

> **Wave:** V1. **Gate:** V0 audit complete (`plan/VIBESAFE-AUDIT.md` reviewed). **Do not start until V0 = done.**

---

## Goal

Make VibeSafe testable, CI-honest, and deterministic-by-default. Ship-quality minor bump (target 1.4.0).

---

## Slice queue

| ID | Branch | Scope | Done when |
|----|--------|-------|-----------|
| V1-A | `pod/v1a-scanner-tests` | vitest + per-scanner fixture tests from `test-data/` | `npm test` green; ≥1 assertion per scanner |
| V1-B | `pod/v1b-version-cleanup` | Sync CLI version to package.json; remove stray `reporting/*.js` if superseded by `.ts` | build clean; single source per module |
| V1-C | `pod/v1c-ci-fixtures` | CI: build + test + scan self with `--high-only` | `.github/workflows/ci.yml` fails on test fail |
| V1-D | `pod/v1d-ai-opt-in` | LLM report only with `--ai-suggestions`; update README | default scan never calls OpenAI |
| V1-E | `pod/v1e-lockfile-cves` | Parse lockfile for transitive CVE lookup | README lockfile caveat removed or updated |

**Order:** V1-B can run parallel with V1-A. V1-C after V1-A. V1-D after V1-B. V1-E last (or skip if audit marks high effort — ask Justin).

---

## V1-A — tests-first (priority)

1. Add `vitest` devDependency
2. `package.json` script: `"test": "vitest run"`
3. For each scanner, at least one test:

```text
tests/scanners/secrets.test.ts      → test-data/aws-secrets-tests.txt, safe-file.txt
tests/scanners/endpoints.test.ts    → test-data/endpoint-test.js, nextjs-endpoint-tests/
tests/scanners/rateLimiting.test.ts → rate-limit-missing.js vs rate-limit-present.js
tests/scanners/httpClient.test.ts   → http-client-unsafe.js vs safe
... etc per audit matrix
```

4. Tests import scanner functions directly — do not shell out to CLI unless e2e slice added later
5. Commit + push `pod/v1a-scanner-tests`; do not merge `main` without Justin

---

## V1-D — deterministic default

- Today: `-r` / `--report` may trigger OpenAI without clear opt-in
- Target: `--ai-suggestions` required for any LLM call; `-r` alone = markdown without AI section
- `.env` / `OPENAI_API_KEY` only read when flag set

---

## Done when (wave)

1. All dispatched V1 slices green on pod branches
2. `plan/ORCHESTRATOR.md` updated with SHAs
3. Justin reviews for npm publish

---

## Out of scope

- New scanners (SAST, Semgrep, etc.)
- `vibesafe install` redesign
- Fundamentals markdown (brainstorm repo)
