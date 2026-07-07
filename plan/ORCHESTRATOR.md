# ORCHESTRATOR — VibeSafe

**Status 2026-07-07:** Wave **V1 foundation** **merged** to `master` via `integrate/v1-foundation` (1.4.0). V1-i/g/e pending.

**Authority:** `plan/HANDOFF-VIBESAFE-AUDIT.md` (V0) → `plan/HANDOFF-VIBESAFE-WAVE-1.md` (V1)

**Brainstorm tracker (optional):** `~/arthor-brainstorm/roadmap/orchestrator-prompt-vibesafe-refresh.md`

---

## Slice queue

| ID | Wave | HANDOFF | Branch | Status |
|----|------|---------|--------|--------|
| V0 | Audit | `HANDOFF-VIBESAFE-AUDIT.md` | — (read-only) | **done** 2026-07-06 |
| V1-A | Foundation | `HANDOFF-VIBESAFE-WAVE-1.md` § V1-A | `pod/v1a-scanner-tests` | **merged** 2026-07-07 |
| V1-B | Foundation | same § V1-B | `pod/v1b-version-cleanup` | **merged** 2026-07-07 |
| V1-C | Foundation | same § V1-C | `pod/v1c-ci-fixtures` | **merged** 2026-07-07 |
| V1-D | Foundation | same § V1-D | `pod/v1d-ai-opt-in` | **merged** 2026-07-07 |
| V1-E | Foundation | same § V1-E | `pod/v1e-lockfile-cves` | pending (v1-f,v1-g) |

**V0 order:** read HANDOFF → fill `plan/VIBESAFE-AUDIT.md` → update this table → stop.

**V1 order (after Justin OK):** V1-A ∥ V1-B → V1-C → V1-D → V1-E (V1-E optional per audit)

---

## Operating rules

1. Read `plan/CONTEXT.md` before any slice.
2. **V0 is read-only** — output is `plan/VIBESAFE-AUDIT.md` only.
3. Tests-first for V1 (`vitest` + `test-data/` fixtures).
4. Branch naming: `pod/<slug>`; push when green; **no merge to `master` without Justin**.
5. Deterministic scanners are P0; LLM calls require explicit `--ai-suggestions` (V1-D).
6. **STOP** on: package rename, arthor repo merge, FastAPI/swarm/GitHub App scope.

---

## Git

- Default branch: `master` (per CI workflow)
- Publish: `npm publish` — Justin only

---

## Meta prompt (paste this entire block)

```
You are the Tier-1 orchestrator for ~/VibeSafe (npm CLI security scanner).

Read FIRST (in order):
1. plan/ORCHESTRATOR.md
2. plan/CONTEXT.md
3. plan/HANDOFF-VIBESAFE-AUDIT.md

You are on Wave V0 — READ-ONLY AUDIT. Do not edit src/, package.json, or CI unless Justin explicitly overrides.

Your deliverable: plan/VIBESAFE-AUDIT.md with all 9 sections from the HANDOFF.

Steps:
1. Read every scanner under src/scanners/ and CLI wiring in src/index.ts
2. Inventory test-data/ fixtures vs scanner coverage
3. Run: npm ci && npm run build && node dist/index.js scan test-data/ --high-only
4. Write plan/VIBESAFE-AUDIT.md (executive summary, scanner matrix, code health, CI gap, AI boundary, noise review, Wave 1 backlog, out-of-scope, course notes)
5. Update plan/ORCHESTRATOR.md — mark V0 done with date
6. Stop. Do not start V1 slices until Justin approves the audit.

Closed decisions (do not re-litigate):
- Keep npm package name "vibesafe"
- Not an Arthor product; no Neon/schema integration
- Swarm/red-team platform is out of scope for this wave
- Deterministic scan is default; AI is opt-in (recommend in audit, implement in V1-D)

If plan/HANDOFF-VIBESAFE-AUDIT.md is missing, say so — it should exist at repo root plan/.

Start: V0 audit now.
```
