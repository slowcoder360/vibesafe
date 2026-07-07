import { FindingSeverity } from './dependencies'; // Re-use severity type
import { DetectedTechnologies } from '../frameworkDetection'; // Import DetectedTechnologies
import path from 'path'; // Import path for relative path calculation

export interface EndpointFinding {
    file: string;
    line: number; // Line where the potential endpoint is defined
    path: string; // The matched endpoint path (e.g., '/admin')
    type: 'Potentially Exposed Debug/Admin Endpoint';
    severity: FindingSeverity;
    message: string;
    details?: string; // Context from the line
}

// Regex patterns for common debug/admin paths
// Includes common web framework patterns and simple string literals
// - Looks for common HTTP method/routing function calls (.get, .post, .use, etc.) followed by a sensitive path string
// - Looks for sensitive path string literals like '/admin', "/debug" etc.
const DEBUG_ADMIN_ENDPOINT_REGEX = /(\.get|\.post|\.put|\.delete|\.use|\.all)\s*\(\s*['"](\/debug|\/admin|\/status|\/info|\/healthz?|\/metrics|\/console|\/manage|\/config)[\/\w\-\:]*['"]/gi;
const DEBUG_ADMIN_STRING_LITERAL_REGEX = /['"](\/debug|\/admin|\/status|\/info|\/healthz?|\/metrics|\/console|\/manage|\/config)[\/\w\-\:]*['"]/gi;

// --- Next.js Specific Constants ---
const NEXTJS_API_BASE_PATHS = ['pages/api/', 'app/api/'];
const NEXTJS_SENSITIVE_ROUTE_KEYWORDS = ['admin', 'debug', 'status', 'info', 'healthz', 'health', 'metrics', 'console', 'manage', 'config'];

/**
 * Helper function to clean Next.js file path segments into identifiable route keywords.
 * e.g., 'pages/api/admin/index.ts' with basePath 'pages/api/' -> { fullRoute: '/api/admin', keywordPart: 'admin' }
 * e.g., 'app/api/status/[id]/route.ts' with basePath 'app/api/' -> { fullRoute: '/api/status/[id]', keywordPart: 'status' }
 */
function cleanNextJsRouteSegment(relativeFilePath: string, basePath: string): { fullRoutePath: string, keywordPart: string } | null {
    if (!relativeFilePath.startsWith(basePath)) return null;

    let route = relativeFilePath.substring(basePath.length);

    // Construct the full route path first (for reporting)
    let fullRoutePath = route.replace(/\.(ts|js|tsx|jsx)$/, ''); // Remove extension
    fullRoutePath = fullRoutePath.replace(/\/index$/, ''); // /api/admin/index -> /api/admin
    fullRoutePath = fullRoutePath.replace(/\/route$/, '');   // /api/admin/route -> /api/admin
    
    // Remove route groups like (group) from the display path as they don't affect the URL
    fullRoutePath = fullRoutePath.replace(/\([^/]+?\)\//g, ''); // e.g. (group)/user -> user/
    fullRoutePath = fullRoutePath.replace(/^\(([^/]+?)\)\//, '');    // e.g. (group)user -> user at start
    // If a group is the last segment, e.g. /api/(group), remove it.
    // Corrected regex to only target parenthesized groups at the end.
    fullRoutePath = fullRoutePath.replace(/\/\(([^/]+?)\)$/, ''); 

    // Public URL prefix is /api/... — strip Next.js filesystem segments (pages/, app/)
    const routePrefix = basePath.replace(/^(pages|app)\/api\/?/, 'api').replace(/\/$/, '');
    const finalFullRoute = ('/' + routePrefix + '/' + fullRoutePath.replace(/^\//, ''))
        .replace(/\/+/g, '/')
        .replace(/\/$/, '') || '/';
    
    // Now, determine the keyword part for matching against sensitive keywords
    // Remove (group) segments for keyword matching, e.g. (dashboard)/settings -> settings
    let keywordFocusedRoute = route;
    const tempParts = keywordFocusedRoute.split('/');
    const keywordPathParts = tempParts.filter(p => !/^[()].*$/.test(p)); // Remove parts like "(group)"
    keywordFocusedRoute = keywordPathParts.join('/');

    const parts = keywordFocusedRoute.split('/');
    let keywordPart = '';

    // Iterate backwards to find the most relevant segment non-dynamic segment
    for (let i = parts.length - 1; i >= 0; i--) {
        const part = parts[i].replace(/\.(ts|js|tsx|jsx)$/, '').replace(/^(index|route)$/, '');
        if (part && !part.startsWith('[') && !part.startsWith('(')) { // Not empty, not dynamic, not a group itself
            keywordPart = part;
            break;
        }
    }
    // If the loop finishes and keywordPart is empty (e.g. pages/api/[id].ts -> parts was just '[id].ts')
    // and parts.length was 1, it means the keyword should be from the dir before it if possible (handled by loop logic)
    // This logic primarily focuses on the last non-dynamic segment as the keyword.

    return { fullRoutePath: finalFullRoute, keywordPart: keywordPart.toLowerCase() };
}


/**
 * Scans file content for potentially exposed debug or admin endpoints.
 * @param rootDir The root directory of the project being scanned.
 * @param filePath Absolute path to the file.
 * @param content The content of the file.
 * @param detectedTech Object indicating detected technologies, including isNextJs.
 * @returns An array of EndpointFinding objects.
 */
export function scanForExposedEndpoints(rootDir: string, filePath: string, content: string, detectedTech: DetectedTechnologies): EndpointFinding[] {
    // console.log(`[scanForExposedEndpoints] File: ${filePath}, DetectedTech: ${JSON.stringify(detectedTech)}`); // DEBUG LOG REMOVED

    // If neither backend nor Next.js specifically detected (though Next.js implies backend), skip.
    if (!detectedTech.hasBackend && !detectedTech.isNextJs) {
        return [];
    }

    const findings: EndpointFinding[] = [];
    const lines = content.split('\n');

    let match;

    // Check for framework-style route definition patterns first (e.g., app.get('/admin'))
    DEBUG_ADMIN_ENDPOINT_REGEX.lastIndex = 0;
    while ((match = DEBUG_ADMIN_ENDPOINT_REGEX.exec(content)) !== null) {
        const fullMatch = match[0];
        const endpointPath = match[2]; // The captured path like '/admin'
        const lineNumber = content.substring(0, match.index).split('\n').length;

        // Avoid adding duplicates for the same line/path if regex matches slightly different parts
        if (!findings.some(f => f.file === filePath && f.line === lineNumber && f.path === endpointPath)) {
            findings.push({
                file: filePath,
                line: lineNumber,
                path: endpointPath,
                type: 'Potentially Exposed Debug/Admin Endpoint',
                severity: 'Medium', // Direct route definition match
                message: `Potential sensitive endpoint path found: ${endpointPath}. Manual verification required.`,
                details: `Sensitive path ${endpointPath} used in route definition near line ${lineNumber}. Ensure proper authentication and authorization controls are in place. Context: ${lines[lineNumber-1].trim().substring(0, 80)}${lines[lineNumber-1].trim().length > 80 ? '...' : ''}`
            });
        }
    }

    // Check for simple string literals as a fallback (lower confidence)
    DEBUG_ADMIN_STRING_LITERAL_REGEX.lastIndex = 0;
    while ((match = DEBUG_ADMIN_STRING_LITERAL_REGEX.exec(content)) !== null) {
        const endpointPath = match[1]; // The captured path like '/admin'
        const lineNumber = content.substring(0, match.index).split('\n').length;

        // De-duplication: Only add if not already found by the more specific framework pattern for the same path and line.
        // Also, if it's a Next.js project and a file-based route already covers this, consider skipping.
        if (!findings.some(f => f.file === filePath && f.line === lineNumber && f.path === endpointPath)) {
            // Further check for Next.js: if a file-based finding for this path exists, maybe skip this regex one.
            // This is tricky because regex might find a string literal for a route not defined by convention.
            findings.push({
                file: filePath,
                line: lineNumber,
                path: endpointPath,
                type: 'Potentially Exposed Debug/Admin Endpoint',
                severity: 'Low', // Lower severity for simple string matches
                message: `Potential sensitive endpoint string found: ${endpointPath}. Manual verification required.`,
                details: `Sensitive path string ${endpointPath} found near line ${lineNumber}. Verify if used in a route and ensure protection. Context: ${lines[lineNumber-1].trim().substring(0, 80)}${lines[lineNumber-1].trim().length > 80 ? '...' : ''}`
            });
        }
    }

    // --- Next.js File-based Route Analysis ---
    if (detectedTech.isNextJs) {
        // console.log(`[Next.js Scan] Processing file: ${filePath} with rootDir: ${rootDir}`); // DEBUG LOG REMOVED
        const relativeFilePath = path.relative(rootDir, filePath);
        // console.log(`[Next.js Scan] Relative path: ${relativeFilePath}`); // DEBUG LOG REMOVED

        for (const basePath of NEXTJS_API_BASE_PATHS) {
            // console.log(`[Next.js Scan] Checking against basePath: ${basePath}`); // DEBUG LOG REMOVED
            if (relativeFilePath.startsWith(basePath)) {
                // console.log(`[Next.js Scan] Match for basePath: ${basePath} with relativeFilePath: ${relativeFilePath}`); // DEBUG LOG REMOVED
                const cleanedRouteInfo = cleanNextJsRouteSegment(relativeFilePath, basePath);
                // console.log(`[Next.js Scan] Cleaned route info: ${JSON.stringify(cleanedRouteInfo)}`); // DEBUG LOG REMOVED

                if (cleanedRouteInfo && cleanedRouteInfo.keywordPart && NEXTJS_SENSITIVE_ROUTE_KEYWORDS.includes(cleanedRouteInfo.keywordPart)) {
                    // console.log(`[Next.js Scan] Sensitive keyword '${cleanedRouteInfo.keywordPart}' found for path: ${cleanedRouteInfo.fullRoutePath}`); // DEBUG LOG REMOVED
                    const { fullRoutePath, keywordPart } = cleanedRouteInfo;
                    
                    // De-duplication: Check if a regex-based finding already exists for this conceptual endpoint.
                    // A simple check: if a regex finding contains the keywordPart in its path for the same file.
                    const alreadyFoundByRegex = findings.some(f => 
                        f.file === filePath && 
                        f.path.toLowerCase().includes(keywordPart) &&
                        (f.path.toLowerCase().endsWith(keywordPart) || f.path.toLowerCase().includes(keywordPart + '/'))
                    );

                    if (!alreadyFoundByRegex) {
                        // Also check if this exact file-based path has somehow already been added (e.g. symlinks, unusual casing)
                        const alreadyExistsAsFileBased = findings.some(f => 
                            f.file === filePath && 
                            f.path === fullRoutePath && 
                            f.line === 1
                        );
                        if(!alreadyExistsAsFileBased){
                            findings.push({
                                file: filePath,
                                line: 1, // For file-based routes, the finding is for the file itself
                                path: fullRoutePath, // The inferred full API route
                                type: 'Potentially Exposed Debug/Admin Endpoint',
                                severity: 'Medium', // File-based is a direct indicator
                                message: `Potential sensitive Next.js API route found by file path: ${fullRoutePath}. Manual verification required.`,
                                details: `Next.js API route convention at '${relativeFilePath}' (resolved to '${fullRoutePath}') matches sensitive keyword '${keywordPart}'. Ensure proper authentication and authorization.`,
                            });
                        }
                    }
                }
                break; // Found a matching base path, no need to check others for this file
            }
        }
    }

    // Final de-duplication (though the checks above should handle most cases)
    return findings.filter((finding, index, self) =>
        index === self.findIndex((f) => (
            f.file === finding.file && f.line === finding.line && f.path === finding.path && f.severity === finding.severity
        ))
    );
} 