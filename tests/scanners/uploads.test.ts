import { describe, it, expect } from 'vitest';
import fs from 'fs';
import path from 'path';
import { scanForUnvalidatedUploads } from '../../src/scanners/uploads';

describe('uploads scanner', () => {
  it('reports missing multer limits when hasBackend is true', () => {
    const file = path.join(__dirname, '../../test-data/multer-test.js');
    const content = fs.readFileSync(file, 'utf-8');

    const findings = scanForUnvalidatedUploads(file, content, true);
    const missingLimits = findings.filter((f) => f.type === 'Missing Upload Size Limit');

    expect(missingLimits.length).toBeGreaterThanOrEqual(1);
  });
});
