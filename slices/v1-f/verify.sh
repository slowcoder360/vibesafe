#!/usr/bin/env bash
set -euo pipefail
cd "$(dirname "$0")/../.."
npm test -- tests/scanners/dependencies.test.ts
node -e "
const { parseDependencies, lookupCves, detectPackageManagers } = require('./dist/scanners/dependencies');
const path = require('path');
const root = path.join(__dirname, 'test-data/vulnerable-deps');
const files = require('fs').readdirSync(root).map(f => path.join(root, f));
const mgrs = detectPackageManagers([path.join(root, 'package.json')], root);
lookupCves(parseDependencies(mgrs)).then(r => {
  const bad = r.filter(d => d.vulnerabilities.length > 0 && d.maxSeverity === 'None');
  if (bad.length) process.exit(1);
  console.log('ok');
});
"
