import fs from 'fs';
import path from 'path';
import axios from 'axios';
import ora from 'ora';

export type PackageManager = 'npm' | 'yarn' | 'pnpm' | 'pip' | 'poetry' | 'maven' | 'gradle' | 'unknown';

// Define severity levels consistently
export type FindingSeverity = 'Info' | 'None' | 'Low' | 'Medium' | 'High' | 'Critical';

interface PackageManagerInfo {
    name: PackageManager;
    manifestFile: string;
    lockFile?: string; // Optional, as not all managers have lock files (e.g., simple requirements.txt)
}

export interface DependencyInfo {
    name: string;
    version: string;
    packageManager: PackageManager;
    sourceFile: string; // e.g., 'package.json'
}

// OSV API related types
interface OSVSeverity {
    type: string; // e.g., "CVSS_V3"
    score: string; // e.g., "7.5"
}

interface OSVulnerability {
    id: string;
    summary?: string;
    details?: string;
    aliases?: string[];
    modified: string;
    published: string;
    database_specific?: any;
    severity?: OSVSeverity[]; // Updated type
    affected: { package: { ecosystem: string; name: string }; ranges: any[] }[];
}

interface OSVApiResponse {
    vulns: OSVulnerability[];
}

interface OSVBatchQuery {
    queries: { package: { name: string; ecosystem: string }; version?: string }[];
}

interface OSVBatchResponse {
    results: (OSVApiResponse | null)[]; // Array corresponding to queries
}

// Structure to hold dependency and its vulnerabilities
export interface DependencyFinding extends DependencyInfo {
    vulnerabilities: OSVulnerability[];
    maxSeverity: FindingSeverity; // Add calculated severity
    error?: string;
}

// Define types for findings
// Add export here
export interface SecretFinding {
  file: string;
  line: number;
  type: string; // e.g., 'AWS Key', 'Generic API Key', 'High Entropy String'
  value: string; // The matched secret or high-entropy string
  severity: 'Low' | 'Medium' | 'High';
}

const KNOWN_MANAGERS: PackageManagerInfo[] = [
    { name: 'npm', manifestFile: 'package.json', lockFile: 'package-lock.json' },
    { name: 'yarn', manifestFile: 'package.json', lockFile: 'yarn.lock' },
    { name: 'pnpm', manifestFile: 'package.json', lockFile: 'pnpm-lock.yaml' },
    { name: 'pip', manifestFile: 'requirements.txt' }, // Basic pip
    { name: 'poetry', manifestFile: 'pyproject.toml', lockFile: 'poetry.lock' }, // Poetry uses pyproject.toml
    { name: 'maven', manifestFile: 'pom.xml' },
    { name: 'gradle', manifestFile: 'build.gradle' }, // Or build.gradle.kts
    // TODO: Add more (Composer, Bundler, Cargo, Go Modules, etc.)
];

const OSV_BATCH_API_URL = 'https://api.osv.dev/v1/querybatch';

// Map our PackageManagers to OSV ecosystem names
const ECOSYSTEM_MAP: Record<PackageManager, string | null> = {
    npm: 'npm',
    yarn: 'npm', // OSV uses 'npm' for yarn as well
    pnpm: 'npm', // and pnpm
    pip: 'PyPI',
    poetry: 'PyPI',
    maven: 'Maven',
    gradle: 'Maven', // Often uses Maven repositories
    unknown: null,
};

// CVSS Score to Severity Mapping (example)
const CVSS_THRESHOLDS: { level: FindingSeverity; minScore: number }[] = [
    { level: 'Critical', minScore: 9.0 },
    { level: 'High', minScore: 7.0 },
    { level: 'Medium', minScore: 4.0 },
    { level: 'Low', minScore: 0.1 },
    // Info severity isn't directly mapped from CVSS, None is for score 0
    { level: 'None', minScore: 0 }, 
];

/**
 * Extracts the highest CVSS v3 score from OSV severity info.
 * @param severities Array of OSV severity objects.
 * @returns The highest CVSS v3 score found, or 0 if none.
 */
function getHighestCvssScore(severities?: OSVSeverity[]): number {
    if (!severities) return 0;
    let maxScore = 0;
    for (const severity of severities) {
        // Prioritize CVSS V3, but might fall back to others if needed
        if (severity.type === 'CVSS_V3') {
            const score = parseFloat(severity.score);
            if (!isNaN(score)) {
                maxScore = Math.max(maxScore, score);
            }
        }
        // TODO: Add fallback logic for other types like CVSS_V2 if necessary
    }
    return maxScore;
}

/**
 * Determines the finding severity based on CVSS score.
 * @param score The CVSS score.
 * @returns The corresponding FindingSeverity.
 */
function scoreToSeverity(score: number): FindingSeverity {
    for (const threshold of CVSS_THRESHOLDS) {
        if (score >= threshold.minScore) {
            return threshold.level;
        }
    }
    return 'None'; // Should not happen if thresholds cover 0
}

const SEVERITY_RANK: Record<FindingSeverity, number> = {
    None: 0,
    Info: 1,
    Low: 2,
    Medium: 3,
    High: 4,
    Critical: 5,
};

function higherSeverity(a: FindingSeverity, b: FindingSeverity): FindingSeverity {
    return SEVERITY_RANK[a] >= SEVERITY_RANK[b] ? a : b;
}

/**
 * Maps OSV/GitHub advisory severity labels (e.g. database_specific.severity) to FindingSeverity.
 */
function mapOsvSeverityLabel(label: string): FindingSeverity | null {
    switch (label.toUpperCase()) {
        case 'CRITICAL':
            return 'Critical';
        case 'HIGH':
            return 'High';
        case 'MODERATE':
        case 'MEDIUM':
            return 'Medium';
        case 'LOW':
            return 'Low';
        default:
            return null;
    }
}

/**
 * Reads ecosystem severity from an OSV vuln when CVSS v3 is absent.
 */
function parseOsvEcosystemSeverity(vuln: OSVulnerability): FindingSeverity | null {
    const raw = vuln.database_specific?.severity;
    if (typeof raw !== 'string') {
        return null;
    }
    return mapOsvSeverityLabel(raw);
}

/**
 * Computes max severity across vulns: CVSS v3 first, then OSV ecosystem severity,
 * else Medium when vulns exist but no score is available (batch API often omits CVSS).
 */
function computeMaxSeverityFromVulns(vulns: OSVulnerability[]): FindingSeverity {
    let maxCvss = 0;
    let maxOsvSeverity: FindingSeverity | null = null;

    for (const vuln of vulns) {
        maxCvss = Math.max(maxCvss, getHighestCvssScore(vuln.severity));
        const osvSeverity = parseOsvEcosystemSeverity(vuln);
        if (osvSeverity) {
            maxOsvSeverity = maxOsvSeverity
                ? higherSeverity(maxOsvSeverity, osvSeverity)
                : osvSeverity;
        }
    }

    if (maxCvss > 0) {
        return scoreToSeverity(maxCvss);
    }
    if (maxOsvSeverity) {
        return maxOsvSeverity;
    }
    // OSV batch responses may omit CVSS; still surface known vulns at Medium minimum.
    return 'Medium';
}

// Define the return type for the detection function
type DetectedFilesMap = { [key in PackageManager]?: { manifest?: string, lock?: string } };

// --- Detection Logic ---

/**
 * Detects package manager files within a list of found files and returns their locations.
 * @param filePaths An array of absolute file paths found during traversal.
 * @param rootDir The root directory of the scan (for context).
 * @returns A map where keys are PackageManager names and values are objects with manifest/lock file paths.
 */
// Update the return type here
export function detectPackageManagers(filePaths: string[], rootDir: string): DetectedFilesMap {
    const detected: Set<PackageManager> = new Set();
    const detectedFiles: DetectedFilesMap = {}; // Use the defined type

    // Create relative paths for easier matching
    const relativeFilePaths = filePaths.map(fp => path.relative(rootDir, fp));

    for (const manager of KNOWN_MANAGERS) {
        // Check if manifest or lock file exists anywhere in the found files
        const foundManifest = relativeFilePaths.find(rfp => path.basename(rfp) === manager.manifestFile);
        const foundLock = manager.lockFile ? relativeFilePaths.find(rfp => path.basename(rfp) === manager.lockFile) : undefined;

        if (foundLock) {
            detected.add(manager.name);
            if (!detectedFiles[manager.name]) detectedFiles[manager.name] = {};
            detectedFiles[manager.name]!.lock = path.join(rootDir, foundLock);
        }
        if (foundManifest) {
            // Only add based on manifest if not already detected by lock file
            if (!foundLock || !detected.has(manager.name)) {
                // Special handling for generic manifests
                 if ((manager.name === 'npm' || manager.name === 'yarn' || manager.name === 'pnpm') && !detected.has('npm') && !detected.has('yarn') && !detected.has('pnpm')) {
                     detected.add('npm'); // Default to npm if only package.json found
                     if (!detectedFiles['npm']) detectedFiles['npm'] = {};
                     detectedFiles['npm']!.manifest = path.join(rootDir, foundManifest);
                 } else if (manager.name === 'poetry') {
                     detected.add(manager.name);
                     if (!detectedFiles[manager.name]) detectedFiles[manager.name] = {};
                     detectedFiles[manager.name]!.manifest = path.join(rootDir, foundManifest);
                 } else if (!(manager.name === 'npm' || manager.name === 'yarn' || manager.name === 'pnpm')) {
                     // Avoid adding npm/yarn/pnpm based only on package.json if a lock was already found
                     detected.add(manager.name);
                     if (!detectedFiles[manager.name]) detectedFiles[manager.name] = {};
                     detectedFiles[manager.name]!.manifest = path.join(rootDir, foundManifest);
                 }
            }
            // Still record manifest location even if lock was found
             if (detectedFiles[manager.name]) {
                 detectedFiles[manager.name]!.manifest = path.join(rootDir, foundManifest);
             }
        }
    }

    // Handle gradle kts variant (if build.gradle wasn't found)
    const foundGradleKts = relativeFilePaths.find(rfp => path.basename(rfp) === 'build.gradle.kts');
    if (!detected.has('gradle') && foundGradleKts) {
        detected.add('gradle');
         if (!detectedFiles['gradle']) detectedFiles['gradle'] = {};
         detectedFiles['gradle']!.manifest = path.join(rootDir, foundGradleKts);
    }

    // Return the map of file locations
    return detectedFiles;
}

// TODO: Implement Phase 3.2: Parse dependencies
// TODO: Implement Phase 3.3: CVE lookup
// TODO: Implement Phase 3.4: Threshold filtering 

/**
 * Parses dependencies from a specific package.json file.
 * @param filePath The absolute path to the package.json file.
 * @returns An array of DependencyInfo objects.
 */
function parsePackageJson(filePath: string): DependencyInfo[] {
    const dependencies: DependencyInfo[] = [];

    if (!fs.existsSync(filePath)) {
        console.warn(`${filePath} not found, cannot parse Node dependencies.`);
        return dependencies;
    }

    try {
        const packageJsonContent = fs.readFileSync(filePath, 'utf-8');
        const packageJson = JSON.parse(packageJsonContent);

        const extractDeps = (depSection: { [key: string]: string } | undefined, manager: PackageManager = 'npm') => {
            if (!depSection) return;
            for (const name in depSection) {
                dependencies.push({
                    name: name,
                    version: depSection[name],
                    packageManager: manager, // Assume npm/yarn/pnpm - could refine later if needed
                    sourceFile: 'package.json'
                });
            }
        };

        extractDeps(packageJson.dependencies);
        extractDeps(packageJson.devDependencies);
        extractDeps(packageJson.peerDependencies); // Optional: include peerDependencies?
        // Optional: include optionalDependencies?

    } catch (error) {
        console.error(`Error parsing ${filePath}:`, error);
    }

    return dependencies;
}

/**
 * Parses dependencies based on detected package managers and their file locations.
 * @param detectedFiles Map of detected managers to their file paths.
 * @returns An array of DependencyInfo objects from all detected managers.
 */
export function parseDependencies(detectedFiles: { [key in PackageManager]?: { manifest?: string, lock?: string } }): DependencyInfo[] {
    let allDependencies: DependencyInfo[] = [];
    // Flag to ensure we only parse node deps once
    let nodeDepsParsed = false;

    // TODO: Implement package-lock.json (and yarn.lock, pnpm-lock.yaml) parsing.
    // - If a lock file is detected (detectedFiles[manager].lock), prioritize parsing it 
    //   to get exact installed versions and transitive dependencies.
    // - Pass the resulting DependencyInfo list (with exact versions) to lookupCves.
    // - Fall back to parsing the manifest file (e.g., package.json) only if no lock file exists.

    for (const manager in detectedFiles) {
        const files = detectedFiles[manager as PackageManager];
        if (!files || !files.manifest) continue; // Need manifest to parse deps

        const manifestPath = files.manifest;

        if ((manager === 'npm' || manager === 'yarn' || manager === 'pnpm') && !nodeDepsParsed) {
            console.log(`Parsing dependencies from ${path.basename(manifestPath)}...`);
            allDependencies = allDependencies.concat(parsePackageJson(manifestPath));
            nodeDepsParsed = true;
        } else if (manager === 'pip') {
             console.log(`Parsing ${path.basename(manifestPath)} not yet implemented.`);
        } else if (manager === 'poetry') {
            console.log(`Parsing ${path.basename(manifestPath)} not yet implemented.`);
        }
        // Add other parsers here based on manager type
    }

    return allDependencies;
}

// TODO: Implement Phase 3.3: CVE lookup
// TODO: Implement Phase 3.4: Threshold filtering 

/**
 * Looks up vulnerabilities and calculates max severity for dependencies.
 * @param dependencies Array of DependencyInfo objects.
 * @returns Array of DependencyFinding objects.
 */
export async function lookupCves(dependencies: DependencyInfo[]): Promise<DependencyFinding[]> {
    const initialFindings: DependencyFinding[] = dependencies.map(dep => ({
        ...dep,
        vulnerabilities: [],
        maxSeverity: 'None', // Initialize severity
        error: ECOSYSTEM_MAP[dep.packageManager] ? undefined : 'Unsupported package manager for CVE lookup'
    }));
    const queries: OSVBatchQuery['queries'] = [];
    const queryIndexToFindingIndex: number[] = []; // Map query index back to initialFindings index

    // Prepare queries for OSV API
    initialFindings.forEach((finding, index) => {
        const ecosystem = ECOSYSTEM_MAP[finding.packageManager];
        if (ecosystem && finding.version && !finding.error) {
            queries.push({
                package: { name: finding.name, ecosystem: ecosystem },
                version: finding.version,
            });
            queryIndexToFindingIndex.push(index); // Store the original index
        }
    });

    if (queries.length === 0) {
        console.log('No dependencies suitable for CVE lookup.');
        return initialFindings;
    }

    const spinner = ora(`Querying OSV.dev for ${queries.length} dependencies...`).start();
    try {
        const response = await axios.post<OSVBatchResponse>(OSV_BATCH_API_URL, { queries });

        if (response.status !== 200 || !response.data || !response.data.results) {
             spinner.fail('OSV API request failed (Invalid Response).');
            throw new Error(`OSV API request failed with status ${response.status}`);
        }

        // Map results back to findings
        response.data.results.forEach((result, queryIdx) => {
            const findingIndex = queryIndexToFindingIndex[queryIdx];
            const targetFinding = initialFindings[findingIndex];

            if (targetFinding) {
                if (result && result.vulns && result.vulns.length > 0) {
                    targetFinding.vulnerabilities = result.vulns;
                    targetFinding.maxSeverity = computeMaxSeverityFromVulns(result.vulns);
                } else {
                    targetFinding.maxSeverity = 'None'; // Explicitly set to None if no vulns found
                }
            } else {
                 console.warn(`Could not map OSV result back for query index ${queryIdx}`);
            }
        });

         spinner.succeed('OSV CVE lookup complete.');

    } catch (error: any) {
        spinner.fail(`OSV API request failed: ${error.message}`);
        // Mark queried dependencies as having an error
        queryIndexToFindingIndex.forEach(findingIndex => {
            if (initialFindings[findingIndex] && !initialFindings[findingIndex].error) {
                 initialFindings[findingIndex].error = 'CVE lookup failed';
                 initialFindings[findingIndex].maxSeverity = 'None'; // Or maybe 'Unknown'?
            }
        });
    }

    return initialFindings;
}

// TODO: Implement Phase 3.4: Threshold filtering 