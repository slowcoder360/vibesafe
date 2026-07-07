import { describe, it, expect } from 'vitest';
import fs from 'fs';
import path from 'path';
import { scanForHttpClientIssues } from '../../src/scanners/httpClient';

describe('httpClient scanner', () => {
  it('detects at least one missing timeout in http-client-unsafe.js', () => {
    const file = path.join(__dirname, '../../test-data/http-client-unsafe.js');
    const content = fs.readFileSync(file, 'utf-8');

    const findings = scanForHttpClientIssues(file, content, true);
    const missingTimeout = findings.filter((f) => f.type === 'Potential Missing Timeout');

    expect(missingTimeout.length).toBeGreaterThanOrEqual(1);
  });
});
