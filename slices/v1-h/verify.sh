#!/usr/bin/env bash
set -euo pipefail
cd "$(dirname "$0")/../.."
npm run build
npm test -- tests/scanners/uploads.test.ts tests/scanners/rateLimiting.test.ts tests/scanners/endpoints.test.ts tests/scanners/httpClient.test.ts
