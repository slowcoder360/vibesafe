import { describe, it, expect } from 'vitest';
import path from 'path';
import { parseDependencies, lookupCves } from '../../src/scanners/dependencies';

describe('dependencies scanner', () => {
  it('finds vulnerabilities for lodash or axios in vulnerable-deps/package.json', async () => {
    const manifestPath = path.join(__dirname, '../../test-data/vulnerable-deps/package.json');
    const dependencies = parseDependencies({
      npm: { manifest: manifestPath },
    });

    expect(dependencies.some((d) => d.name === 'lodash' || d.name === 'axios')).toBe(true);

    const findings = await lookupCves(dependencies);
    const vulnerable = findings.filter(
      (f) => (f.name === 'lodash' || f.name === 'axios') && f.vulnerabilities.length > 0,
    );

    expect(vulnerable.length).toBeGreaterThan(0);
  });
});
