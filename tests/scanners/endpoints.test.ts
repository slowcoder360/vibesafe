import { describe, it, expect } from 'vitest';
import fs from 'fs';
import path from 'path';
import { scanForExposedEndpoints } from '../../src/scanners/endpoints';

const detectedTech = {
  hasFrontend: false,
  hasBackend: true,
  isNextJs: false,
  hasAuth: false,
  hasMiddleware: false,
  hasHttpClient: false,
  hasCors: false,
  hasFileUpload: false,
};

describe('endpoints scanner', () => {
  it('flags /admin with Medium or higher severity in endpoint-test.js', () => {
    const rootDir = path.join(__dirname, '../../test-data');
    const file = path.join(rootDir, 'endpoint-test.js');
    const content = fs.readFileSync(file, 'utf-8');

    const findings = scanForExposedEndpoints(rootDir, file, content, detectedTech);
    const adminFindings = findings.filter(
      (f) => f.path.includes('/admin') && (f.severity === 'Medium' || f.severity === 'High' || f.severity === 'Critical'),
    );

    expect(adminFindings.length).toBeGreaterThanOrEqual(1);
  });
});
