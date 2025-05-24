import OpenAI from 'openai';
import { SecretFinding } from '../scanners/secrets';
import { DependencyFinding, FindingSeverity } from '../scanners/dependencies';
import { ConfigFinding } from '../scanners/configuration';
import { UploadFinding } from '../scanners/uploads';
import { EndpointFinding } from '../scanners/endpoints';
import { RateLimitFinding } from '../scanners/rateLimiting';
import { LoggingFinding } from '../scanners/logging';
import { HttpClientFinding } from '../scanners/httpClient';
import chalk from 'chalk';
import { GitignoreWarning } from '../utils/fileTraversal';

export interface ReportData {
    secretFindings: SecretFinding[];
    dependencyFindings: DependencyFinding[];
    configFindings: ConfigFinding[];
    uploadFindings: UploadFinding[];
    endpointFindings: EndpointFinding[];
    rateLimitFindings: RateLimitFinding[];
    loggingFindings: LoggingFinding[];
    httpClientFindings: HttpClientFinding[];
    gitignoreWarnings: GitignoreWarning[];
    infoSecretFindings: SecretFinding[];
}

// Limit the amount of data sent to the LLM to manage cost/context window
const MAX_SECRETS_FOR_AI = 10;
const MAX_DEPS_FOR_AI = 15;
const MAX_CONFIG_FOR_AI = 10;
const MAX_UPLOADS_FOR_AI = 10;
const MAX_ENDPOINTS_FOR_AI = 10;
const MAX_RATELIMIT_FOR_AI = 5;
const MAX_LOGGING_FOR_AI = 10;
const MAX_HTTPCLIENT_FOR_AI = 10;

// Type for the simplified finding structure sent to the AI
interface SimplifiedFinding {
    file?: string;
    line?: number;
    type: string;
    severity: FindingSeverity | SecretFinding['severity'] | UploadFinding['severity'];
    message: string;
    details?: string;
    packageName?: string;
    version?: string;
    vulnerabilities?: any[];
}

const MAX_FINDINGS_PER_TYPE = 10;

/**
 * Generates AI-powered suggestions for fixing findings.
 * @param reportData The aggregated findings.
 * @param openaiConf OpenAI API key and url.
 * @param model model name.
 * @returns A promise resolving to a Markdown string with suggestions.
 */
export async function generateAISuggestions(reportData: ReportData, openaiConf: {baseURL:string, apiKey: string}, model: string): Promise<string> {
    const openai = new OpenAI(openaiConf);

    // Prepare a simplified list of findings for the prompt
    const simplifiedFindings: SimplifiedFinding[] = [
        ...reportData.secretFindings.slice(0, MAX_FINDINGS_PER_TYPE).map(f => ({ file: f.file, line: f.line, type: f.type, severity: f.severity, message: `Secret finding: ${f.type}` })),
        ...reportData.dependencyFindings.slice(0, MAX_FINDINGS_PER_TYPE).map(d => ({
            packageName: d.name,
            version: d.version,
            type: 'Vulnerable Dependency',
            severity: d.maxSeverity,
            message: `${d.vulnerabilities.length} vulnerabilities found. Highest severity: ${d.maxSeverity}. Example CVE: ${d.vulnerabilities[0]?.id || 'N/A'}`,
            vulnerabilities: d.vulnerabilities.slice(0, 3)
        })),
        ...reportData.configFindings.slice(0, MAX_FINDINGS_PER_TYPE).map(c => ({ file: c.file, type: c.type, severity: c.severity, message: c.message })),
        ...reportData.uploadFindings.slice(0, MAX_FINDINGS_PER_TYPE).map(u => ({ file: u.file, line: u.line, type: u.type, severity: u.severity, message: u.message, details: u.details })),
        ...reportData.endpointFindings.slice(0, MAX_FINDINGS_PER_TYPE).map(e => ({ file: e.file, line: e.line, type: e.type, severity: e.severity, message: e.message, details: e.details })),
        ...reportData.loggingFindings.slice(0, MAX_FINDINGS_PER_TYPE).map(l => ({ file: l.file, line: l.line, type: l.type, severity: l.severity, message: l.message, details: l.details })),
        ...reportData.httpClientFindings.slice(0, MAX_FINDINGS_PER_TYPE).map(h => ({ file: h.file, line: h.line, type: h.type, severity: h.severity, message: h.message, details: h.details }))
    ];

    if (simplifiedFindings.length === 0) {
        return "\n*AI Suggestions: No specific findings requiring actionable suggestions were identified.*\n";
    }

    const prompt = `
        Given the following security findings from the VibeSafe scanner, provide concise, actionable suggestions for fixing each one. 
        Focus on practical code changes or configuration updates where possible. 
        Group suggestions by finding type or file if it makes sense. Be brief.

        Findings:
        ${JSON.stringify(simplifiedFindings, null, 2)}

        Suggestions (provide in Markdown format):
    `;

    try {
        const completion = await openai.chat.completions.create({
            model: model,
            messages: [
                { role: "system", content: "You are a helpful security assistant providing fix suggestions for code vulnerabilities." },
                { role: "user", content: prompt }
            ],
            max_tokens: 500,
            temperature: 0.3,
        });

        const suggestions = completion.choices[0]?.message?.content?.trim() || "AI failed to generate suggestions.";

        return `\n## AI Suggestions\n\n${suggestions}\n`;

    } catch (error: any) {
        console.error(chalk.red("Error calling OpenAI API:"), error.message);
        return `\n## AI Suggestions\n\n*Error generating suggestions. Please check your OpenAI API key and connectivity.*\nError details: ${error.message}\n`;
    }
}
 