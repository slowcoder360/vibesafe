import { describe, it, expect } from 'vitest';
import { scanFileForSecrets } from '../../src/scanners/secrets';
import path from 'path';

describe('secrets scanner', () => {
  it('detects High severity AWS keys in aws-secrets-tests.txt', () => {
    const file = path.join(__dirname, '../../test-data/aws-secrets-tests.txt');
    const findings = scanFileForSecrets(file);
    const high = findings.filter((f) => f.severity === 'High');
    expect(high.length).toBeGreaterThanOrEqual(1);
  });

  it('returns no High findings for safe-file.txt', () => {
    const file = path.join(__dirname, '../../test-data/safe-file.txt');
    const findings = scanFileForSecrets(file);
    const high = findings.filter((f) => f.severity === 'High');
    expect(high).toHaveLength(0);
  });
});
