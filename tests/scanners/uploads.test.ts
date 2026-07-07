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

  it('detects fileUpload() from express-fileupload import without limits', () => {
    const file = path.join(__dirname, '../../test-data/express-fileupload-test.js');
    const content = fs.readFileSync(file, 'utf-8');

    const findings = scanForUnvalidatedUploads(file, content, true);
    const unrestricted = findings.filter(
      (f) => f.type === 'Potentially Unrestricted Upload Library Usage',
    );

    expect(unrestricted.length).toBeGreaterThanOrEqual(1);
  });
});
