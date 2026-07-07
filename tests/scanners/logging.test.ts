import { describe, it, expect } from 'vitest';
import fs from 'fs';
import path from 'path';
import { scanForLoggingIssues } from '../../src/scanners/logging';

describe('logging scanner', () => {
  it('detects at least one PII finding in logging-test.js', () => {
    const file = path.join(__dirname, '../../test-data/logging-test.js');
    const content = fs.readFileSync(file, 'utf-8');

    const findings = scanForLoggingIssues(file, content, true);
    const piiFindings = findings.filter((f) => f.type === 'Potential PII Logging');

    expect(piiFindings.length).toBeGreaterThanOrEqual(1);
  });
});
