import { describe, it, expect } from 'vitest';
import path from 'path';
import { scanConfigFile } from '../../src/scanners/configuration';

describe('configuration scanner', () => {
  it('detects CORS High and DEBUG Medium in app.config.json', () => {
    const file = path.join(__dirname, '../../test-data/app.config.json');
    const findings = scanConfigFile(file);

    const corsHigh = findings.filter(
      (f) => f.type === 'Permissive CORS' && f.severity === 'High',
    );
    const debugMedium = findings.filter(
      (f) => f.type === 'Insecure Setting' && f.severity === 'Medium',
    );

    expect(corsHigh.length).toBeGreaterThanOrEqual(1);
    expect(debugMedium.length).toBeGreaterThanOrEqual(1);
  });
});
