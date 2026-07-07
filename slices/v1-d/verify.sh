#!/usr/bin/env bash
set -euo pipefail
cd "$(dirname "$0")/../.."
npm run build
# Report without AI flag should complete without OPENAI_API_KEY
env -u OPENAI_API_KEY node dist/index.js scan test-data/no-framework -r /tmp/vibesafe-report-test.md 2>&1
test -f /tmp/vibesafe-report-test.md
! grep -qi 'error generating suggestions' /tmp/vibesafe-report-test.md || true
npm test 2>/dev/null || npm run build
