# VibeSafe Audit — Wave V0

**Date:** 2026-07-06  
**Auditor:** Tier-1 orchestrator (read-only)  
**Repo:** `~/vibesafe` @ `master` (local)  
**Method:** Source review + `npm ci && npm run build && node dist/index.js scan test-data/ --high-only`

---

## 1. Executive summary

- **Ship-readiness:** Functional CLI with 8 deterministic scanners and rich `test-data/` fixtures, but **not publish-ready for a minor bump** — no automated tests, CI does not exercise built artifacts correctly, and several correctness bugs hide real High/Critical findings.
- **Biggest risk:** Dependency CVE severity mapping returns `None` for packages with dozens of known GHSA IDs (`test-data/vulnerable-deps/`), so `--high-only` and exit-code logic **miss vulnerable dependencies entirely**.
- **Second risk:** Aggregate scans of multi-project trees pick **one arbitrary `package.json`**, so nested fixtures (`vulnerable-deps/`, `nextjs-endpoint-tests/`) are invisible unless scanned as subdirectories.
- **Third risk:** `-r/--report` always invokes OpenAI (or configured LLM URL) — violates deterministic-by-default invariant; network + API key required for markdown reports today.
- **Top 3 Wave 1 wins:**
  1. **V1-A + V1-C** — vitest per scanner against `test-data/` + CI that runs `npm test` on the **local build** (not `npx vibesafe` from registry).
  2. **V1-D** — `--ai-suggestions` opt-in; `-r` alone produces deterministic markdown.
  3. **Fix CVE severity + multi-manifest discovery** (propose as **V1-F** before or with V1-E) — without this, dependency scanning is unreliable in production use.
- **Fixture hygiene:** `test-data/aws-secrets-tests.txt` contains synthetic AWS-shaped strings (expected); no live credentials observed in repo source. Values not reproduced in this report.
- **Dev dependency hygiene:** `npm audit` reports 9 vulns (4 high) in dev tree — pre-publish cleanup recommended in V1-B scope extension or separate hygiene pass.

---

## 2. Scanner matrix

| Scanner | Inputs | Severity rules | Network? | Test fixture exists? | Gaps |
|---------|--------|----------------|----------|----------------------|------|
| **Secrets** | All traversed text files (binary ext skipped) | AWS keys High; generic API key Medium; entropy Low; `.env` → Info | No | `aws-secrets-tests.txt`, `config.js`, `safe-file.txt` | README/CONTEXT claim JWT + SSH — **not implemented** (`secrets.ts` TODO). Entropy duplicates regex hits. Dead `checkEntropy()` stub. |
| **Dependencies** | Single `package.json` per scan root | CVSS v3 → Critical/High/Medium/Low; else `None` | Yes (OSV batch API) | `vulnerable-deps/package.json` (subdir only) | **Only one manifest** when multiple exist. Lockfiles ignored in traversal. **CVSS missing → `None` despite vulns**. Version ranges not resolved. pip/poetry/maven parsers stubbed. |
| **Configuration** | `.json`, `.yaml`, `.yml` | DEBUG/devMode Medium; CORS `*` High | No | `app.config.json` | Top-level + shallow nested CORS only. No `.js` config (`config.js` secrets only). |
| **HTTP client** | `.js/.ts/.jsx/.tsx` when `hasBackend` | Missing timeout/signal Low | No | `http-client-unsafe.js`, `http-client-safe.js`, `superagent-test.js` | **False positives** on `http-client-safe.js` (superagent `.timeout()` chained after initial call). No retry/cancellation depth. |
| **Uploads** | `.js/.ts/.jsx/.tsx/.vue/.html` when `hasBackend` | Missing limits Medium; generic Low | No | `multer-test.js`, `formidable-test.js`, `generic-upload-test.js`, `upload-form.html` | **`express-fileupload-test.js` never fires** — regex expects `expressUpload()` but fixture uses `fileUpload()`. `hasBackend` gates all upload checks. |
| **Endpoints** | `.js/.ts/.jsx/.tsx` when `hasBackend` or Next.js | Route match Medium; string literal Low; Next file-path Medium | No | `endpoint-test.js`, `nextjs-endpoint-tests/` (subdir) | Next.js paths wrong (`/pages/api/admin` vs `/api/admin`). `/health`, `/info` over-broad. Not run at aggregate root for Next fixtures without subdir scan. |
| **Rate limiting** | `package.json` deps + route file heuristics | Project advisory Low | No | `rate-limit-missing.js`, `rate-limit-present.js` | **Only checks deps**, not `require('express-rate-limit')` in source. Advisory fires on aggregate `test-data/` even when `rate-limit-present.js` present. `@fastify/rate-limit` in framework list but not in `KNOWN_RATE_LIMIT_PACKAGES`. |
| **Logging** | `.js/.ts/.jsx/.tsx` when `hasBackend` | PII keyword Medium; unsanitized error Low | No | `logging-test.js`, `backend-express/index.js` | Keyword false positives (`'Connecting with key:'`). AST parse failures silently skipped. |
| **Install heuristics** | npm registry metadata | Age/downloads/readme/license/repo warnings | Yes | (manual only) | Out of V1 scope per HANDOFF; no fixture tests. |

### `test-data/` fixture inventory (by scanner)

| Fixture | Secrets | Deps | Config | HTTP | Upload | Endpoint | Rate | Logging |
|---------|---------|------|--------|------|--------|----------|------|---------|
| `aws-secrets-tests.txt` | ✓ | | | | | | | |
| `safe-file.txt` | ✓ (negative) | | | | | | | |
| `config.js` | ✓ | | | | | | | ✓ |
| `app.config.json` | | | ✓ | | | | | |
| `vulnerable-deps/` | | ✓ | | | | | | |
| `http-client-unsafe.js` | | | | ✓ | | | | |
| `http-client-safe.js` | | | | ✓ (FP) | | | | |
| `superagent-test.js` | | | | ✓ | | | | ✓ |
| `multer-test.js` | | | | | ✓ | | | |
| `formidable-test.js` | | | | | ✓ | | | |
| `express-fileupload-test.js` | | | | | ✗ gap | | | |
| `generic-upload-test.js` | | | | | ✓ | | | |
| `upload-form.html` | | | | | ✓ | | | |
| `endpoint-test.js` | | | | | | ✓ | | |
| `nextjs-endpoint-tests/` | | ✓ | | | | ✓ | ✓ | |
| `backend-express/` | | ✓ | | ✓ | | ✓ | ✓ | ✓ |
| `rate-limit-missing.js` | | | | | | ✓ | ✓ | |
| `rate-limit-present.js` | | | | | | ✓ | ✗ gap | |
| `logging-test.js` | ✓ | | | | | | | ✓ |
| `no-framework/`, `frontend-react/` | | ✓ (tech) | | | | | | |
| `fullstack-next/` | | ✓ | | | | partial | | |

---

## 3. Code health

### TypeScript quality

- Widespread `any` usage (`index.ts`, scanners, reporting, installer) — ~40+ occurrences across `src/`.
- Duplicate type export: `SecretFinding` defined in both `secrets.ts` and `dependencies.ts` with incompatible severity unions.
- Stale TODOs in production paths (`secrets.ts` entropy TODO already implemented; `dependencies.ts` lockfile TODOs).
- `frameworkDetection.ts` includes `rate-limiter-flexible` in middleware list but `rateLimiting.ts` uses a separate smaller package set.

### Duplicate artifacts

- `src/reporting/markdown.js` and `src/reporting/aiSuggestions.js` sit alongside `.ts` sources — not in `"files"` publish set but confuse contributors and may drift from `dist/`.

### Version drift

| Source | Version |
|--------|---------|
| `package.json` | `1.3.5` |
| `src/index.ts` `program.version()` | `0.0.1` |

### Dependencies (`package.json`)

| Package | Role | Note |
|---------|------|------|
| `@typescript-eslint/parser` + `types` | AST (logging, httpClient) | Runtime dep — could be devDependency if only used at scan time (acceptable for CLI) |
| `axios` | OSV client | Required for CVE lookup |
| `openai` | AI suggestions | Should not load on default scan path (V1-D) |
| `chalk`, `commander`, `ora`, `dotenv`, `ignore`, `js-yaml` | CLI | Reasonable |

`npm audit` (dev tree): **9 vulnerabilities (4 high)** — picomatch ReDoS chain via tooling; run `npm audit fix` before publish.

### Error handling

- **File I/O:** Per-file try/catch in upload/endpoint/logging/http scans — warns and continues (good).
- **OSV API:** Spinner + marks deps `error: 'CVE lookup failed'` on failure; does not fail exit code.
- **AST parse:** Silent catch in logging/httpClient — no diagnostic at default verbosity.
- **Traversal:** Permission errors warn; missing dirs error-logged.

---

## 4. CI / release

### What CI proves today (`.github/workflows/ci.yml`)

1. `npm ci` + `npm run build` (tsc)
2. `npx vibesafe scan --high-only` on repo root

### Gaps vs "green = safe to publish minor bump"

| Gap | Impact |
|-----|--------|
| **No `npm test`** | Script exits 1 by design — zero regression signal |
| **`npx vibesafe` ≠ local build** | `node_modules/.bin/vibesafe` absent after `npm ci`; CI likely runs **published npm package**, not branch under test |
| **Self-scan only** | `test-data/` ignored via root `.vibesafeignore` — fixtures never exercised in CI |
| **No fixture assertions** | High findings on self-scan are unvalidated against expected counts |
| **Exit code semantics** | `--high-only` exits 1 on High; normal scan always exits 0 even with High secrets |
| **No publish gate** | No version bump check, no `npm pack` dry-run |

**Recommendation (V1-C):** `npm test` + `node dist/index.js scan test-data/ --high-only` with fixture-based tests asserting minimum finding counts per subdirectory.

---

## 5. AI / deterministic boundary

### Where LLM is invoked today

| Trigger | Code path | Default behavior |
|---------|-----------|------------------|
| `vibesafe scan -r` / `--report` | `generateMarkdownReport()` → `generateAISuggestions()` | **Always calls OpenAI-compatible API** |
| `--url` / `--model` flags | Passed through to `OpenAI` client | Default URL `https://api.openai.com` |
| `dotenv/config` at top of `index.ts` | Loads `OPENAI_API_KEY` globally | Key read even when not reporting |

`scan` without `-r` does **not** call LLM — deterministic for console/JSON output.

### Recommendation (implement V1-D — do not implement in V0)

- Add flag: **`--ai-suggestions`**
- Behavior:
  - `-r` alone → markdown table + summary, **no** `generateAISuggestions()` call
  - `-r --ai-suggestions` → append AI section; read `OPENAI_API_KEY` / `--url` / `--model` only then
  - Document: AI requires network; core scan remains offline-capable except OSV

---

## 6. False positive / noise review

**Command run:** `node dist/index.js scan test-data/ --high-only`  
**Exit code:** 1 (9 High secrets, 1 High config; deps/httpClients empty in filtered output)

### Samples per category

| Category | Fixture | Finding | Verdict |
|----------|---------|---------|---------|
| Secrets | `aws-secrets-tests.txt` | 9× High AWS patterns | **True positive** (synthetic test vectors) |
| Secrets | `config.js` | Generic API key Medium (filtered out of `--high-only`) | True positive |
| Config | `app.config.json` | CORS `*` High | True positive |
| Config | `app.config.json` | DEBUG Medium (filtered by `--high-only`) | True positive |
| Uploads | `multer-test.js` | Missing limits Medium (in full scan; 3 upload findings in high-only include 2 multer) | True positive |
| Endpoints | `endpoint-test.js` | `/admin`, `/debug`, `/status` Medium | True positive (heuristic) |
| Endpoints | `endpoint-test.js` | `/info`, `/metrics` Low string literals | Noisy but acceptable at Low |
| Logging | `config.js` | PII `'key'` in log label Medium | **False positive** (label text, not secret value) |
| Logging | `logging-test.js` | PII patterns | True positives for test file |
| HTTP | `http-client-safe.js` | superagent missing timeout Low (full scan) | **False positive** — `.timeout()` chained on next line |
| HTTP | `http-client-unsafe.js` | All libraries flagged | True positives |
| Deps | `vulnerable-deps/` (subdir) | 32 GHSA IDs, `maxSeverity: None` | **False negative** at High filter |
| Rate limit | aggregate `test-data/` | Advisory despite `rate-limit-present.js` | **False positive** — import not in package.json |

### Noise themes

1. Entropy scanner duplicates AWS regex hits as Low "High Entropy String"
2. `/status` and `/health` endpoints flagged in apps that may intentionally expose health checks
3. Superagent/request chain analysis too shallow
4. Gitignore warning fires on `test-data/` (no `.gitignore` in fixture tree) — expected noise for that path

---

## 7. Wave 1 slice backlog (proposed)

| ID | Title | Effort | Risk | Depends |
|----|-------|--------|------|---------|
| **V1-A** | vitest + per-scanner fixture tests (`tests/scanners/*.test.ts`) | M | Low | — |
| **V1-B** | Sync CLI version; remove `src/reporting/*.js`; `npm audit fix` dev deps | S | Low | — |
| **V1-C** | CI: `npm test` + `node dist/index.js scan test-data/` (not `npx vibesafe`) | S | Low | V1-A |
| **V1-D** | `--ai-suggestions` opt-in; `-r` deterministic default | S | Med | V1-B |
| **V1-F** | CVE severity fallback when CVSS absent; fail `--high-only` on any OSV hit | M | Med | V1-A |
| **V1-G** | Multi-`package.json` discovery (monorepo / nested fixtures) | M | Med | V1-A |
| **V1-H** | Scanner correctness bundle: express-fileupload regex, rate-limit import AST, Next path prefix, superagent chain | M | Med | V1-A |
| **V1-E** | Lockfile CVE parsing (`package-lock`, `yarn.lock`, `pnpm-lock`) | L | High | V1-F, V1-G |
| **V1-I** | Exit code policy: fail on High/Critical by default (document `--no-fail`) | S | Low | V1-C |

**Suggested dispatch order:** V1-A ∥ V1-B → V1-F + V1-H → V1-C → V1-D → V1-G → V1-E (optional per Justin).

---

## 8. Out of scope (explicit)

Deferred — **STOP without Justin approval:**

- FastAPI hosted backend, repo cloning, PR comments
- Semgrep, TruffleHog, Nuclei, Nmap, Metasploit, ZAP, FFUF integration
- AI swarm / red-team / honeypot / killbox platform (`arthor-brainstorm/inbox/idea4.md` vision)
- GitHub App or hosted scan service
- Merge into `arthor-*` repos or Neon/schema integration
- npm package rename from `vibesafe`
- New scanner categories (SAST, IaC, container scanning)
- `vibesafe install` redesign (typosquatting DB, install script audit)
- Fundamentals curriculum files in this repo

---

## 9. Course integration notes (brief)

| Module | Hook | Teaching moment |
|--------|------|-----------------|
| **07 — Secrets** | `vibesafe scan` on a project with `.env` | `.env` → Info severity; stress `.gitignore`; show AWS/generic key findings from `test-data/aws-secrets-tests.txt` |
| **09 — Verify what AI built** | `vibesafe scan --high-only` after vibe-coding a feature | Run before ship; interpret endpoint/upload/logging heuristics as "manual review required", not proof of exploit |
| **Cross-cut** | `vibesafe scan -o results.json` | JSON output for CI; contrast with `-r` (deterministic after V1-D) vs `--ai-suggestions` (optional remediation narrative) |

No curriculum files added in V0. Brainstorm trackers: `~/arthor-brainstorm/inbox/vibesafe-refresh-intake.md`, `~/arthor-brainstorm/roadmap/orchestrator-prompt-vibesafe-refresh.md`.

---

## Appendix: V0 scan summary (`test-data/` aggregate, `--high-only`)

| Category | Count |
|----------|-------|
| Secrets (High) | 9 |
| Configuration (High) | 1 |
| Uploads (Medium+, included in high-only filter) | 3 |
| Endpoints (Medium+, included) | 4 |
| Logging (Medium+, included) | 8 |
| Dependencies | 0 (wrong manifest + severity bug) |
| HTTP clients | 0 (Low severity excluded) |
| Rate limit advisory | 0 (Low excluded) |

**Green-review gate:** Justin approves this document → unblock V1 slices per `plan/HANDOFF-VIBESAFE-WAVE-1.md`.
