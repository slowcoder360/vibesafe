import { describe, it, expect } from 'vitest';
import path from 'path';
import { checkRateLimitHeuristic } from '../../src/scanners/rateLimiting';
import type { DependencyInfo } from '../../src/scanners/dependencies';

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

describe('rateLimiting scanner', () => {
  it('issues advisory when routes exist but no rate-limit package is in dependencies', () => {
    const missingFile = path.join(__dirname, '../../test-data/rate-limit-missing.js');
    const dependencies: DependencyInfo[] = [
      {
        name: 'express',
        version: '4.18.0',
        packageManager: 'npm',
        sourceFile: 'package.json',
      },
    ];

    const findings = checkRateLimitHeuristic(dependencies, [missingFile], detectedTech);

    expect(findings.length).toBe(1);
    expect(findings[0].type).toBe('Project-Level Rate Limit Advisory');
  });

  it('returns no advisory when express-rate-limit is in dependencies', () => {
    const presentFile = path.join(__dirname, '../../test-data/rate-limit-present.js');
    const dependencies: DependencyInfo[] = [
      {
        name: 'express',
        version: '4.18.0',
        packageManager: 'npm',
        sourceFile: 'package.json',
      },
      {
        name: 'express-rate-limit',
        version: '6.7.0',
        packageManager: 'npm',
        sourceFile: 'package.json',
      },
    ];

    const findings = checkRateLimitHeuristic(dependencies, [presentFile], detectedTech);

    expect(findings).toHaveLength(0);
  });

  it('returns no advisory when express-rate-limit is imported in source but not in package.json', () => {
    const presentFile = path.join(__dirname, '../../test-data/rate-limit-present.js');
    const dependencies: DependencyInfo[] = [
      {
        name: 'express',
        version: '4.18.0',
        packageManager: 'npm',
        sourceFile: 'package.json',
      },
    ];

    const findings = checkRateLimitHeuristic(dependencies, [presentFile], detectedTech);

    expect(findings).toHaveLength(0);
  });
});
