import { parse } from '@typescript-eslint/typescript-estree';
import { TSESTree } from '@typescript-eslint/types';
import { FindingSeverity } from './dependencies';

export interface HttpClientFinding {
    file: string;
    line: number; // Line number where the HTTP client call occurs
    type: 'Potential Missing Timeout' | 'Potential Missing Retry' | 'Missing Request Cancellation'; // Add more types as needed
    severity: FindingSeverity;
    library: 'axios' | 'fetch' | 'got' | 'superagent' | 'request' | 'unknown'; // Library detected
    message: string;
    details?: string; // Context like the function/method called
}

/**
 * Scans file content using AST for HTTP client calls lacking recommended configurations (e.g., timeouts).
 * Currently focuses on detecting missing timeouts in axios, fetch, got, superagent, and request.
 * TODO: Implement retry logic checks.
 * @param filePath Absolute path to the file.
 * @param content The content of the file.
 * @param hasBackend Indicates whether the file is likely a backend context.
 * @returns An array of HttpClientFinding objects.
 */
export function scanForHttpClientIssues(filePath: string, content: string, hasBackend: boolean): HttpClientFinding[] {
    // Skip if not likely a backend context
    if (!hasBackend) {
        return [];
    }

    const findings: HttpClientFinding[] = [];
    try {
        const ast = parse(content, { loc: true, range: true, comment: false }); // loc: true gives line/column numbers
        const parentMap = new Map<TSESTree.Node, TSESTree.Node>();

        // Simple visitor pattern implementation
        function visit(node: TSESTree.Node | null, parent: TSESTree.Node | null = null) {
            if (!node) return;
            if (parent) {
                parentMap.set(node, parent);
            }

            if (node.type === TSESTree.AST_NODE_TYPES.CallExpression) {
                checkForHttpClientCall(node, filePath, findings, parentMap);
            }

            // Recursively visit children
            for (const key in node) {
                // eslint-disable-next-line no-prototype-builtins
                if (node.hasOwnProperty(key)) {
                    const child = (node as any)[key];
                    if (typeof child === 'object' && child !== null) {
                        if (Array.isArray(child)) {
                            child.forEach((item) => visit(item, node));
                        } else {
                            visit(child, node);
                        }
                    }
                }
            }
        }

        visit(ast);

    } catch (error: any) {
        // Ignore parsing errors (e.g., invalid JS/TS) - could log if needed
        // console.warn(`AST Parsing error in ${filePath}: ${error.message}`);
    }

    return findings;
}

// List of known axios methods that make requests
const AXIOS_REQUEST_METHODS = new Set(['request', 'get', 'delete', 'head', 'options', 'post', 'put', 'patch']);
// List of known superagent methods that initiate requests
const SUPERAGENT_REQUEST_METHODS = new Set(['get', 'post', 'put', 'patch', 'delete', 'del', 'head', 'options']);
// List of known got methods that make requests
const GOT_REQUEST_METHODS = new Set(['get', 'post', 'put', 'patch', 'head', 'delete', 'stream']);

// Superagent methods (often chained like .get().send() but initial method is key)
const SUPERAGENT_METHODS = new Set(['get', 'post', 'put', 'patch', 'delete', 'del', 'head', 'options']);

/**
 * Returns true when a superagent request call is part of a chain that includes .timeout().
 */
function superagentChainHasTimeout(
    node: TSESTree.CallExpression,
    parentMap: Map<TSESTree.Node, TSESTree.Node>,
): boolean {
    let current: TSESTree.Node | undefined = node;
    while (current) {
        const parent = parentMap.get(current);
        if (!parent) break;
        if (
            parent.type === TSESTree.AST_NODE_TYPES.CallExpression &&
            parent.callee.type === TSESTree.AST_NODE_TYPES.MemberExpression &&
            parent.callee.property.type === TSESTree.AST_NODE_TYPES.Identifier &&
            parent.callee.property.name === 'timeout'
        ) {
            return true;
        }
        current = parent;
    }
    return false;
}

/**
 * Checks a CallExpression node to see if it's a known HTTP client call
 * and if it might be missing timeout configurations.
 */
function checkForHttpClientCall(
    node: TSESTree.CallExpression,
    filePath: string,
    findings: HttpClientFinding[],
    parentMap: Map<TSESTree.Node, TSESTree.Node>,
) {
    const callee = node.callee;
    let library: HttpClientFinding['library'] = 'unknown';
    let callDetail = '';
    let missingTimeout = false;
    let line = node.loc.start.line;

    // --- Check for axios --- 
    if (callee.type === TSESTree.AST_NODE_TYPES.MemberExpression && 
        callee.object.type === TSESTree.AST_NODE_TYPES.Identifier && 
        callee.object.name === 'axios' &&
        callee.property.type === TSESTree.AST_NODE_TYPES.Identifier &&
        AXIOS_REQUEST_METHODS.has(callee.property.name)) { 
        library = 'axios';
        callDetail = `axios.${callee.property.name}`;
        const configArg = [...node.arguments].reverse().find(arg => arg.type === TSESTree.AST_NODE_TYPES.ObjectExpression);
        missingTimeout = !configArg || !objectHasProperty(configArg as TSESTree.ObjectExpression, ['timeout', 'signal']);
    } else if (callee.type === TSESTree.AST_NODE_TYPES.Identifier && callee.name === 'axios') {
        library = 'axios';
        callDetail = 'axios';
        let configArg: TSESTree.Node | undefined = undefined;
        if (node.arguments.length === 1 && node.arguments[0].type === TSESTree.AST_NODE_TYPES.ObjectExpression) {
             configArg = node.arguments[0]; 
        } else if (node.arguments.length > 1 && node.arguments[1].type === TSESTree.AST_NODE_TYPES.ObjectExpression) {
             configArg = node.arguments[1]; 
        }
        missingTimeout = !configArg || !objectHasProperty(configArg as TSESTree.ObjectExpression, ['timeout', 'signal']);
    }
    // --- Check for fetch --- 
    else if (callee.type === TSESTree.AST_NODE_TYPES.Identifier && callee.name === 'fetch') {
        library = 'fetch';
        callDetail = 'fetch';
        const optionsArg = node.arguments[1];
        missingTimeout = !optionsArg || optionsArg.type !== TSESTree.AST_NODE_TYPES.ObjectExpression || !objectHasProperty(optionsArg, ['signal']);
    }
    // --- Check for got --- 
    else if (callee.type === TSESTree.AST_NODE_TYPES.Identifier && callee.name === 'got') {
        library = 'got';
        callDetail = 'got';
        const optionsArg = node.arguments[1]; 
        missingTimeout = !optionsArg || optionsArg.type !== TSESTree.AST_NODE_TYPES.ObjectExpression || !objectHasProperty(optionsArg, ['timeout', 'signal']);
    } else if (callee.type === TSESTree.AST_NODE_TYPES.MemberExpression && 
               callee.object.type === TSESTree.AST_NODE_TYPES.Identifier && 
               callee.object.name === 'got' &&
               callee.property.type === TSESTree.AST_NODE_TYPES.Identifier &&
               GOT_REQUEST_METHODS.has(callee.property.name)) {
         library = 'got';
         callDetail = `got.${callee.property.name}`;
         const optionsArg = node.arguments[1];
         missingTimeout = !optionsArg || optionsArg.type !== TSESTree.AST_NODE_TYPES.ObjectExpression || !objectHasProperty(optionsArg, ['timeout', 'signal']);
    }
    // --- Check for request (deprecated) --- 
    else if (callee.type === TSESTree.AST_NODE_TYPES.Identifier && callee.name === 'request') {
        library = 'request';
        callDetail = 'request';
        const optionsArg = node.arguments[0];
        if (optionsArg && optionsArg.type === TSESTree.AST_NODE_TYPES.ObjectExpression) {
             missingTimeout = !objectHasProperty(optionsArg, ['timeout']);
        } else if (node.arguments.length > 1 && node.arguments[1]?.type === TSESTree.AST_NODE_TYPES.ObjectExpression) {
             missingTimeout = !objectHasProperty(node.arguments[1] as TSESTree.ObjectExpression, ['timeout']);
        } else {
             missingTimeout = true; 
        }
    } else if (callee.type === TSESTree.AST_NODE_TYPES.MemberExpression && 
               callee.object.type === TSESTree.AST_NODE_TYPES.Identifier && 
               callee.object.name === 'request' &&
               callee.property.type === TSESTree.AST_NODE_TYPES.Identifier) { 
         library = 'request';
         callDetail = `request.${callee.property.name}`;
         const optionsArg = node.arguments[0]; 
         if (optionsArg && optionsArg.type === TSESTree.AST_NODE_TYPES.ObjectExpression) {
             missingTimeout = !objectHasProperty(optionsArg, ['timeout']);
         } else if (node.arguments.length > 1 && node.arguments[1]?.type === TSESTree.AST_NODE_TYPES.ObjectExpression) {
             missingTimeout = !objectHasProperty(node.arguments[1] as TSESTree.ObjectExpression, ['timeout']);
         } else {
              missingTimeout = true;
         }
    }
    // --- Check for superagent --- 
    else if (callee.type === TSESTree.AST_NODE_TYPES.Identifier && callee.name === 'superagent') {
        library = 'superagent';
        callDetail = 'superagent(...)';
        missingTimeout = !superagentChainHasTimeout(node, parentMap);
    } else if (callee.type === TSESTree.AST_NODE_TYPES.MemberExpression && 
               callee.object.type === TSESTree.AST_NODE_TYPES.Identifier && 
               callee.object.name === 'superagent' &&
               callee.property.type === TSESTree.AST_NODE_TYPES.Identifier &&
               SUPERAGENT_METHODS.has(callee.property.name)) {
         library = 'superagent';
         callDetail = `superagent.${callee.property.name}`;
         missingTimeout = !superagentChainHasTimeout(node, parentMap);
    } else if (callee.type === TSESTree.AST_NODE_TYPES.MemberExpression &&
               callee.object.type === TSESTree.AST_NODE_TYPES.CallExpression &&
               callee.object.callee.type === TSESTree.AST_NODE_TYPES.Identifier &&
               callee.object.callee.name === 'superagent') {
         library = 'superagent'; 
         callDetail = `superagent(...).${callee.property.type === TSESTree.AST_NODE_TYPES.Identifier ? callee.property.name : 'method'}`;
         missingTimeout = !superagentChainHasTimeout(node, parentMap);
    }

    // Add finding logic...
    if (library !== 'unknown' && missingTimeout) {
        if (!findings.some(f => f.file === filePath && f.line === line && f.library === library && f.type === 'Potential Missing Timeout')) {
            let message = `Potential missing timeout or cancellation signal in ${library} call.`;
            let details = `Call found: ${callDetail} near line ${line}. Review configuration for timeouts or cancellation.`;

            // Customize message/details for superagent due to chained methods
            if (library === 'superagent') {
                message = `Potential missing timeout/cancellation in ${library} call (unable to check chained methods).`;
                details = `Call found: ${callDetail} near line ${line}. Superagent timeouts are often set via chained .timeout(). Please manually verify timeout/cancellation configuration.`;
            }
            // Customize message/details for fetch to mention AbortController
            else if (library === 'fetch') {
                message = `Potential missing cancellation signal in ${library} call.`;
                details = `Call found: ${callDetail} near line ${line}. Fetch requests should use an AbortController signal in the options for timeout/cancellation.`;
            }

            findings.push({
                file: filePath,
                line: line,
                type: 'Potential Missing Timeout', 
                severity: 'Low', 
                library: library,
                message: message, // Use customized message
                details: details  // Use customized details
            });
        }
    }
}

/**
 * Helper to check if an ObjectExpression node has specific property keys.
 */
function objectHasProperty(node: TSESTree.ObjectExpression | TSESTree.ObjectPattern | undefined, propertyNames: string[]): boolean {
    if (!node || node.type !== TSESTree.AST_NODE_TYPES.ObjectExpression) return false;
    return node.properties.some(prop => 
        prop.type === TSESTree.AST_NODE_TYPES.Property &&
        prop.key.type === TSESTree.AST_NODE_TYPES.Identifier &&
        propertyNames.includes(prop.key.name)
    );
}