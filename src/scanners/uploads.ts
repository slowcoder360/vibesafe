import { FindingSeverity } from './dependencies'; // Re-use severity type

export interface UploadFinding {
    file: string;
    line: number; // Line where the pattern is found
    type: 
        | 'Missing Upload Size Limit' 
        | 'Missing Upload File Filter' 
        | 'Generic File Upload Pattern' 
        | 'Potentially Unrestricted Upload Library Usage'; // New type for libraries where config check is basic
    severity: FindingSeverity;
    message: string;
    details?: string; // Optional details about the pattern found
}

// --- Library Import/Require Patterns ---
// Combined regex to detect imports/requires of common upload libraries
const UPLOAD_LIB_IMPORT_REGEX = /require\(['"](multer|busboy|formidable|connect-multiparty|express-fileupload|graphql-upload|fastify-multipart|koa-body|@koa\/multer|connect-busboy)['"]\)|import .* from ['"](multer|busboy|formidable|connect-multiparty|express-fileupload|graphql-upload|fastify-multipart|koa-body|@koa\/multer|connect-busboy)['"]/g;

// --- Multer Specific Patterns ---
const MULTER_INIT_REGEX = /multer\(\s*(\{[\s\S]*?\}|\))\s*\)/g;
const MULTER_LIMITS_REGEX = /\blimits\s*:/;
const MULTER_FILTER_REGEX = /\bfileFilter\s*:/;

// --- Formidable Specific Patterns ---
const FORMIDABLE_INIT_REGEX = /new\s+Formidable\s*\((.*?)\)/g; // Capture options
const FORMIDABLE_OPTIONS_VAR_REGEX = /const\s+(\w+)\s*=\s*\{\s*.*?maxFileSize\s*:/; // If options are in a variable
const FORMIDABLE_MAXFILESIZE_REGEX = /\bmaxFileSize\s*:/;

// --- Express-FileUpload Specific Patterns ---
// Common import alias: const fileUpload = require('express-fileupload'); app.use(fileUpload());
const EXPRESS_FILEUPLOAD_INIT_REGEX = /(?:expressUpload|fileUpload)\((.*?)\)/g;
const EXPRESS_FILEUPLOAD_LIMITS_REGEX = /\blimits\s*:/; // Check for limits option

// --- Generic Upload Patterns ---
const NEW_FORMDATA_REGEX = /new\s+FormData\s*\(/g;
const INPUT_TYPE_FILE_REGEX = /<input[\s\S]+?type\s*=\s*['"]file['"][\s\S]*?>/gi;

/**
 * Checks if any known upload library is imported/required in the content.
 * @param content File content.
 * @returns An array of detected library names.
 */
function detectUploadLibraries(content: string): string[] {
    const detected: Set<string> = new Set();
    let match;
    UPLOAD_LIB_IMPORT_REGEX.lastIndex = 0;
    while ((match = UPLOAD_LIB_IMPORT_REGEX.exec(content)) !== null) {
        // Match group 1 is from require, group 2 is from import
        const library = match[1] || match[2]; 
        if (library) {
            detected.add(library);
        }
    }
    return Array.from(detected);
}

/**
 * Scans file content for potential unvalidated file upload patterns.
 * Includes checks for specific libraries and generic patterns.
 * @param filePath Absolute path to the file.
 * @param content The content of the file.
 * @param hasBackend Indicates whether the file is part of a backend framework.
 * @returns An array of UploadFinding objects.
 */
export function scanForUnvalidatedUploads(filePath: string, content: string, hasBackend: boolean): UploadFinding[] {
    // If no backend framework detected, skip this scan as validation happens server-side
    if (!hasBackend) {
        return [];
    }

    let findings: UploadFinding[] = [];
    const lines = content.split('\n');
    const detectedLibraries = detectUploadLibraries(content);

    // --- Specific Library Checks --- 
    if (detectedLibraries.includes('multer')) {
        let match;
        MULTER_INIT_REGEX.lastIndex = 0;
        while ((match = MULTER_INIT_REGEX.exec(content)) !== null) {
            const fullMatch = match[0];
            const optionsPart = match[1]; 
            const lineNumber = content.substring(0, match.index).split('\n').length;
            const hasLimits = optionsPart ? MULTER_LIMITS_REGEX.test(optionsPart) : false;
            const hasFilter = optionsPart ? MULTER_FILTER_REGEX.test(optionsPart) : false;

            if (!hasLimits) {
                findings.push({
                    file: filePath, line: lineNumber, type: 'Missing Upload Size Limit',
                    severity: 'Medium', message: 'Potential missing file size limit in multer configuration.',
                    details: `Multer initialized near line ${lineNumber}. Consider adding limits: { fileSize: ... }. Found: ${fullMatch.substring(0, 50)}...`
                });
            }
            if (!hasFilter) {
                findings.push({
                    file: filePath, line: lineNumber, type: 'Missing Upload File Filter',
                    severity: 'Medium', message: 'Potential missing file type filter in multer configuration.',
                    details: `Multer initialized near line ${lineNumber}. Consider adding fileFilter. Found: ${fullMatch.substring(0, 50)}...`
                });
            }
        }
    }

    if (detectedLibraries.includes('formidable')) {
        let match;
        FORMIDABLE_INIT_REGEX.lastIndex = 0;
        while ((match = FORMIDABLE_INIT_REGEX.exec(content)) !== null) {
            const fullMatch = match[0];
            const optionsPart = match[1] || ''; // Options passed directly
            const lineNumber = content.substring(0, match.index).split('\n').length;
            // Basic check: does the direct options string contain maxFileSize?
            const hasDirectMaxFileSize = FORMIDABLE_MAXFILESIZE_REGEX.test(optionsPart);
            // TODO: Add check for options passed as a variable (more complex regex/AST needed)
            
            if (!hasDirectMaxFileSize) { 
                findings.push({
                    file: filePath, line: lineNumber, type: 'Missing Upload Size Limit',
                    severity: 'Medium', message: 'Potential missing maxFileSize limit in Formidable configuration.',
                    details: `Formidable initialized near line ${lineNumber}. Consider adding maxFileSize option. Found: ${fullMatch.substring(0, 80)}...`
                });
            }
            // Formidable often relies on manual checks post-upload for type, less direct config pattern
        }
    }

    if (detectedLibraries.includes('express-fileupload')) {
         let match;
        // Simple check: if the library is used, flag potential lack of default limits
        // This is a basic check as limits might be configured elsewhere or globally
        EXPRESS_FILEUPLOAD_INIT_REGEX.lastIndex = 0;
         while ((match = EXPRESS_FILEUPLOAD_INIT_REGEX.exec(content)) !== null) {
            const fullMatch = match[0];
            const optionsPart = match[1] || '';
            const lineNumber = content.substring(0, match.index).split('\n').length;
            const hasLimits = EXPRESS_FILEUPLOAD_LIMITS_REGEX.test(optionsPart);
            
            if (!hasLimits) {
                findings.push({
                    file: filePath, line: lineNumber, type: 'Potentially Unrestricted Upload Library Usage',
                    severity: 'Low', // Lower severity as config might be elsewhere
                    message: 'express-fileupload used; ensure limits are configured.',
                    details: `express-fileupload initialized near line ${lineNumber}. Default limits might be permissive. Review configuration for size limits. Found: ${fullMatch.substring(0, 80)}...`
                });
            }
         }
         // If no explicit init found, but library is imported, maybe add a general low finding?
    }
    
    // TODO: Add specific checks for other detected libraries (busboy, koa-body, etc.)
    // These often require more complex checks (event handlers, stream piping)


    // --- Generic Pattern Checks --- 
    let genericMatch;
    NEW_FORMDATA_REGEX.lastIndex = 0;
    while((genericMatch = NEW_FORMDATA_REGEX.exec(content)) !== null) {
        const lineNumber = content.substring(0, genericMatch.index).split('\n').length;
        // Avoid duplicates if specific library check already flagged this line
        if (!findings.some(f => f.line === lineNumber && f.file === filePath)) {
            findings.push({
                file: filePath, line: lineNumber, type: 'Generic File Upload Pattern',
                severity: 'Low', message: 'Found `new FormData()`, which is often used for file uploads.',
                details: `Potential file upload handling near line ${lineNumber}. Ensure server-side validation (size, type) is implemented.`
            });
        }
    }

    INPUT_TYPE_FILE_REGEX.lastIndex = 0;
    while((genericMatch = INPUT_TYPE_FILE_REGEX.exec(content)) !== null) {
        const lineNumber = content.substring(0, genericMatch.index).split('\n').length;
        const lastFinding = findings[findings.length - 1];
        // Basic duplicate prevention for this specific regex
        if (lastFinding && lastFinding.type === 'Generic File Upload Pattern' && 
            lastFinding.message.includes('<input type="file">') && 
            (lastFinding.line === lineNumber || lastFinding.line === lineNumber -1)) {
            continue;
        }
        // Avoid duplicates if specific library check already flagged this line
        if (!findings.some(f => f.line === lineNumber && f.file === filePath)) {
            findings.push({
                file: filePath, line: lineNumber, type: 'Generic File Upload Pattern',
                severity: 'Low', message: 'Found `<input type="file">`, indicating a file upload form element.',
                details: `Potential file upload form element near line ${lineNumber}. Ensure associated server-side logic validates uploads.`
            });
        }
    }

    // Final de-duplication based on file, line, and type
    findings = findings.filter((finding, index, self) =>
        index === self.findIndex((f) => ( 
            f.file === finding.file && f.line === finding.line && f.type === finding.type
        ))
    );

    return findings;
} 