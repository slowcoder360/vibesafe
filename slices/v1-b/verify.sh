#!/usr/bin/env bash
set -euo pipefail
cd "$(dirname "$0")/../.."
PKG_VER=$(node -p "require('./package.json').version")
CLI_VER=$(node dist/index.js --version 2>/dev/null || true)
test "$PKG_VER" = "$CLI_VER"
test ! -f src/reporting/markdown.js
test ! -f src/reporting/aiSuggestions.js
npm run build
