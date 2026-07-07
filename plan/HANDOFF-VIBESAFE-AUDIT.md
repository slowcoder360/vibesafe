# HANDOFF — V0 read-only audit

> **Wave:** V0 (read-only). **Branch:** none — no code changes. **Blocks:** Wave 1 slices.

---

## Goal

Produce `plan/VIBESAFE-AUDIT.md`: structured inventory of code health, scanner coverage, false-positive risk, and a prioritized improvement backlog for Wave 1–2.

**No implementation in V0.** Audit only.

---

## Read first

1. `plan/CONTEXT.md`
2. `README.md`
3. `src/index.ts` — CLI wiring, default flags, AI report path
4. Every file under `src/scanners/`
5. `src/reporting/` — note `.js` vs `.ts` duplication
6. `test-data/` — list fixtures; note which scanners each exercises
7. `.github/workflows/ci.yml`
8. `package.json` — scripts, deps, version

---

## Audit sections (required in output)

Write all sections to **`plan/VIBESAFE-AUDIT.md`**:

### 1. Executive summary

- 5–10 bullets: ship-readiness, biggest risks, top 3 wins for Wave 1

### 2. Scanner matrix

| Scanner | Inputs | Severity rules | Network? | Test fixture exists? | Gaps |
|---------|--------|----------------|----------|----------------------|------|

### 3. Code health

- TypeScript quality issues (any `any`, dead code, duplicate `.js` artifacts)
- Version drift (`index.ts` vs `package.json`)
- Dependency audit (outdated, unnecessary deps)
- Error handling on file I/O and OSV API failures

### 4. CI / release

- What CI actually proves today
- Gap vs "green = safe to publish minor bump"

### 5. AI / deterministic boundary

- Where OpenAI is invoked today
- Recommendation: default-off flag name + behavior (do not implement in V0)

### 6. False positive / noise review

- Run `npm run build && node dist/index.js scan test-data/ --high-only` locally
- Sample 3 fixtures per scanner category; note noisy rules

### 7. Wave 1 slice backlog (proposed)

Ordered table:

| ID | Title | Effort | Risk | Depends |
|----|-------|--------|------|---------|

Minimum slices to propose:

- **V1-A** — vitest + fixture tests per scanner
- **V1-B** — fix version drift + remove duplicate `.js` in reporting
- **V1-C** — CI runs `npm test` + fixture suite
- **V1-D** — AI suggestions opt-in (`--ai-suggestions`), default off
- **V1-E** — lockfile CVE support (package-lock / yarn.lock / pnpm-lock)

### 8. Out of scope (explicit)

List anything that looks like swarm/GitHub-app/hosted platform — deferred.

### 9. Course integration notes (brief)

- Which fundamentals modules (07, 09) get a `vibesafe scan` teach hook
- No curriculum files in this repo in V0

---

## Done when

1. `plan/VIBESAFE-AUDIT.md` exists with all 9 sections filled
2. `plan/ORCHESTRATOR.md` slice table updated: V0 = **done**
3. No other files modified (read-only wave)
4. Report tip: if any secrets found in repo during audit, note severity only — do not paste values

---

## STOP — ask Justin

- Recommending npm package rename
- Recommending merge into arthor-* repo
- Any hosted-service or GitHub App architecture
- Deleting scanners without replacement plan
