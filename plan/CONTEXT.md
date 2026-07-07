# CONTEXT — VibeSafe

Shared language for orchestrator and slice workers. No brainstorm paths — this repo is self-contained.

---

## Product identity

- **What:** npm CLI (`vibesafe`) for deterministic security heuristics on local codebases.
- **What it is NOT:** Arthor product, hosted GitHub app, or AI swarm red-team platform (future fork only).
- **Distribution:** npm package `vibesafe` (~1k downloads). Keep package name unless Justin explicitly approves rename.

---

## Commands

| Command | Purpose |
|---------|---------|
| `vibesafe scan [dir]` | Run all scanners on a directory |
| `vibesafe scan -o file.json` | JSON output |
| `vibesafe scan -r [file.md]` | Markdown report |
| `vibesafe scan --high-only` | Filter to High/Critical |
| `vibesafe install <pkg>` | Pre-install trust heuristics |

---

## Source layout

```text
src/
  index.ts              # CLI entry (commander)
  frameworkDetection.ts
  scanners/             # One file per scanner domain
  reporting/            # markdown + aiSuggestions
  installer/            # vibesafe install
  utils/fileTraversal.ts
test-data/              # Fixture projects for manual/CI scan — becomes test oracle source
dist/                   # tsc output (published)
```

---

## Scanners (current)

| Scanner | File | Notes |
|---------|------|-------|
| Secrets | `scanners/secrets.ts` | AWS, JWT, SSH, high-entropy, `.env` |
| Dependencies | `scanners/dependencies.ts` | OSV.dev; direct deps only (lockfile gap) |
| Configuration | `scanners/configuration.ts` | DEBUG, CORS, devMode flags |
| HTTP client | `scanners/httpClient.ts` | Missing timeouts/abort |
| Uploads | `scanners/uploads.ts` | multer, formidable, etc. |
| Endpoints | `scanners/endpoints.ts` | `/admin`, Next.js API routes |
| Rate limiting | `scanners/rateLimiting.ts` | Heuristic: API routes without limit pkg |
| Logging | `scanners/logging.ts` | Sensitive data in logs |

---

## Invariants (do not break without Justin)

1. **Deterministic by default** — `scan` must not call LLM APIs unless user passes explicit AI flag (see Wave 1 slice).
2. **Offline-capable** — core scan works without network except OSV CVE lookup for deps.
3. **npm publish surface** — only `dist/`, README, LICENSE, package.json in `"files"`.
4. **No scope creep** — FastAPI backend, Semgrep/Nuclei integration, GitHub PR comments = **STOP, ask Justin**.

---

## Known gaps (pre-audit)

- `npm test` exits 1 — no unit tests
- `reporting/*.js` duplicates alongside `.ts`
- CLI `--version` (0.0.1) ≠ `package.json` version (1.3.5)
- CI runs self-scan only; does not assert fixture findings
- Lockfile CVE support advertised as "coming soon" in README

---

## External references (operator only)

- Adam fundamentals placement: Module 07 (secrets), Module 09 (verify what AI built)
- BuilderOS skills (if worker has disk access): `~/builder-os/skills/tests-first/SKILL.md`, `security-audit/SKILL.md`
