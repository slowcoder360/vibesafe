import { parse } from '@typescript-eslint/typescript-estree';
import { TSESTree } from '@typescript-eslint/types';
import { FindingSeverity } from './dependencies'; // Re-use severity type

// Renamed interface and added new type
export interface LoggingFinding {
    file: string;
    line: number; 
    type: 'Potential Unsanitized Error Logging' | 'Potential PII Logging'; // Added PII type
    severity: FindingSeverity;
    message: string;
    details?: string; 
    snippet?: string; // Added for PII context
}

// Constants for identifying logger calls
const LOGGER_OBJECT_NAMES = new Set(['console', 'log', 'logger']);
const LOGGER_METHOD_NAMES = new Set(['log', 'info', 'warn', 'error', 'debug']);
const SENSITIVE_DATA_REGEX = /password|email|token|ssn|secret|key|credential/i; // PII Regex

// Renamed function, using AST now
/**
 * Scans file content using AST for potential logging issues:
 * - Logging unsanitized error objects/stack traces.
 * - Logging potentially sensitive data (PII).
 * @param filePath Absolute path to the file.
 * @param content The content of the file.
 * @returns An array of LoggingFinding objects.
 */
export function scanForLoggingIssues(filePath: string, content: string): LoggingFinding[] {
    const findings: LoggingFinding[] = [];
    try {
        const ast = parse(content, { loc: true, range: true, comment: false }); 

        function visit(node: TSESTree.Node | null) {
            if (!node) return;

            if (node.type === TSESTree.AST_NODE_TYPES.CallExpression && 
                node.callee.type === TSESTree.AST_NODE_TYPES.MemberExpression &&
                node.callee.property.type === TSESTree.AST_NODE_TYPES.Identifier &&
                LOGGER_METHOD_NAMES.has(node.callee.property.name)) 
            {
                if (node.callee.object.type === TSESTree.AST_NODE_TYPES.Identifier &&
                    LOGGER_OBJECT_NAMES.has(node.callee.object.name)) 
                {
                    const loggerObjectName = node.callee.object.name;
                    const loggerMethodName = node.callee.property.name;
                    const line = node.loc.start.line;
                    const fullCallText = content.substring(node.range[0], node.range[1]); // Get text of the full call
                    
                    // --- Check 1: Unsanitized Error Logging --- 
                    if (node.arguments.length >= 1) {
                        const firstArg = node.arguments[0];
                        let isPotentialError = false;
                        let errorVarName = '';

                        if (firstArg.type === TSESTree.AST_NODE_TYPES.Identifier && 
                            (firstArg.name === 'err' || firstArg.name === 'error' || firstArg.name === 'e')) 
                        {
                            isPotentialError = true;
                            errorVarName = firstArg.name;
                        } else if (firstArg.type === TSESTree.AST_NODE_TYPES.MemberExpression && 
                                   firstArg.property.type === TSESTree.AST_NODE_TYPES.Identifier && 
                                   firstArg.property.name === 'stack') 
                        {
                             isPotentialError = true;
                             // Attempt to get the object name (e.g., `error.stack`)
                             errorVarName = content.substring(firstArg.range[0], firstArg.range[1]);
                        }

                        if (isPotentialError) {
                             // Avoid duplicate error findings for the same line
                             if (!findings.some(f => f.file === filePath && f.line === line && f.type === 'Potential Unsanitized Error Logging')) {
                                findings.push({
                                    file: filePath,
                                    line: line,
                                    type: 'Potential Unsanitized Error Logging',
                                    severity: 'Low',
                                    message: `Potential logging of unsanitized error object/stack trace using variable '${errorVarName}'.`,
                                    details: `Found call: ${fullCallText.substring(0, 100)}${fullCallText.length > 100 ? '...' : ''}`,
                                    snippet: fullCallText.substring(0, 200) // Add snippet for context
                                });
                             }
                        }
                    }
                    
                    // --- Check 2: PII Logging --- 
                    node.arguments.forEach((arg, index) => {
                        // We need range information to extract text
                        if (arg.range) {
                            const argText = content.substring(arg.range[0], arg.range[1]);
                            const piiMatch = SENSITIVE_DATA_REGEX.exec(argText);

                            if (piiMatch) {
                                const matchedKeyword = piiMatch[0]; // Get the specific keyword matched
                                // Avoid duplicate PII findings for the same line and *roughly* same argument text snippet
                                const snippetPreview = argText.substring(0, 100).trim();
                                if (!findings.some(f => f.file === filePath && 
                                                       f.line === line && 
                                                       f.type === 'Potential PII Logging' &&
                                                       f.snippet?.startsWith(snippetPreview))) 
                                {
                                    findings.push({
                                        file: filePath,
                                        line: line,
                                        type: 'Potential PII Logging',
                                        severity: 'Medium', // PII leaks are generally more sensitive
                                        message: `Potential logging of sensitive data (matched keyword: '${matchedKeyword}').`,
                                        details: `Found potential PII in argument ${index + 1} of ${loggerObjectName}.${loggerMethodName} call near line ${line}. Snippet: ${snippetPreview}${argText.length > 100 ? '...' : ''}`,
                                        snippet: argText.substring(0, 200) // Store the argument text
                                    });
                                }
                            }
                        }
                    });
                }
                // Future: Could potentially check if node.callee.object is itself a CallExpression
                // returning a logger instance, but that adds complexity.
            }

            // Recursively visit children
            for (const key in node) {
                // eslint-disable-next-line no-prototype-builtins
                if (node.hasOwnProperty(key)) {
                    const child = (node as any)[key];
                    if (typeof child === 'object' && child !== null) {
                        if (Array.isArray(child)) {
                            child.forEach(visit);
                        } else {
                            visit(child);
                        }
                    }
                }
            }
        }

        visit(ast);

    } catch (error: any) {
        // console.warn(`AST Parsing error in ${filePath}: ${error.message}`);
    }

    return findings;
} 