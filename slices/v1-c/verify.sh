#!/usr/bin/env bash
set -euo pipefail
cd "$(dirname "$0")/../.."
grep -q 'npm test' .github/workflows/ci.yml
grep -q 'dist/index.js scan' .github/workflows/ci.yml
! grep -q 'npx vibesafe' .github/workflows/ci.yml
npm ci && npm run build && npm test
