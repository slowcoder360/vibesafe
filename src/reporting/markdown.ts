import { SecretFinding } from '../scanners/secrets';
import { DependencyFinding, FindingSeverity } from '../scanners/dependencies';
import { ConfigFinding } from '../scanners/configuration';
import { UploadFinding } from '../scanners/uploads';
import { EndpointFinding } from '../scanners/endpoints';
import { RateLimitFinding } from '../scanners/rateLimiting';
import { LoggingFinding } from '../scanners/logging';
import { HttpClientFinding } from '../scanners/httpClient';
import { GitignoreWarning } from '../utils/fileTraversal';
import { generateAISuggestions } from './aiSuggestions';
import path from 'path';
import ora from 'ora';
import chalk from 'chalk';

// Helper to map severities for consistent ordering/counting
const severityOrder: Record<FindingSeverity | SecretFinding['severity'], number> = {
    'Critical': 5,
    'High': 4,
    'Medium': 3,
    'Low': 2,
    'Info': 1,
    'None': 0
};

interface ReportData {
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

// Helper to map severities to emojis and sort order
function getSeverityInfo(severity: FindingSeverity | SecretFinding['severity'] | UploadFinding['severity'] | EndpointFinding['severity'] | LoggingFinding['severity'] | HttpClientFinding['severity']) {
    switch (severity) {
        case 'Critical': return { emoji: '🚨', sortKey: 0 };
        case 'High': return { emoji: '🔥', sortKey: 1 };
        case 'Medium': return { emoji: '⚠️', sortKey: 2 };
        case 'Low': return { emoji: 'ℹ️', sortKey: 3 }; // Use info emoji for Low
        case 'Info': return { emoji: '💡', sortKey: 4 };
        case 'None': return { emoji: '✅', sortKey: 5 };
        default: return { emoji: '❓', sortKey: 6 };
    }
}

/**
 * Generates a Markdown report summarizing the scan findings.
 * @param reportData The aggregated findings.
 * @returns A Markdown formatted string.
 */
export async function generateMarkdownReport(reportData: ReportData, url: string, model: string  = 'gpt-4.1-nano'): Promise<string> {
    let markdown = `# VibeSafe Security Scan Report ✨🛡️\n\n`;
    markdown += `Generated: ${new Date().toISOString()}\n\n`;

    // Summary Section
    const totalIssues = reportData.secretFindings.length +
                        reportData.dependencyFindings.filter(d => d.vulnerabilities.length > 0).length +
                        reportData.configFindings.length +
                        reportData.uploadFindings.length +
                        reportData.endpointFindings.length +
                        reportData.rateLimitFindings.length +
                        reportData.loggingFindings.length +
                        reportData.httpClientFindings.length;

    const highSeverityIssues = reportData.secretFindings.filter(f => f.severity === 'High').length +
                               reportData.dependencyFindings.filter(d => d.maxSeverity === 'High' || d.maxSeverity === 'Critical').length + // Include Critical
                               reportData.configFindings.filter(f => f.severity === 'High' || f.severity === 'Critical').length +
                               reportData.uploadFindings.filter(f => f.severity === 'High' || f.severity === 'Critical').length +
                               reportData.endpointFindings.filter(f => f.severity === 'High' || f.severity === 'Critical').length +
                               // Rate limit is Low, Logging/HTTP Client unlikely High/Critical
                               reportData.loggingFindings.filter(f => f.severity === 'High' || f.severity === 'Critical').length +
                               reportData.httpClientFindings.filter(f => f.severity === 'High' || f.severity === 'Critical').length;

    markdown += `## 📊 Summary\n\n`;
    markdown += `- **Total Issues Found:** ${totalIssues}\n`;
    markdown += `- **High/Critical Severity Issues:** ${highSeverityIssues}\n`;
    if (reportData.infoSecretFindings.length > 0) {
        markdown += `- **Informational Findings (.env secrets):** ${reportData.infoSecretFindings.length}\n`;
    }
    if (reportData.gitignoreWarnings.length > 0) {
        markdown += `- **Configuration Warnings:** ${reportData.gitignoreWarnings.length}\n`;
    }
    markdown += `\n`;

    // --- Detailed Findings --- 
    markdown += `## 🚨 Detailed Findings\n\n`;

    const allFindings: any[] = [
        ...reportData.secretFindings.map(f => ({ ...f, findingCategory: 'Secret' as const })),
        ...reportData.dependencyFindings.map(f => ({ ...f, findingCategory: 'Dependency' as const })),
        ...reportData.configFindings.map(f => ({ ...f, findingCategory: 'Config' as const })),
        ...reportData.uploadFindings.map(f => ({ ...f, findingCategory: 'Upload' as const })),
        ...reportData.endpointFindings.map(f => ({ ...f, findingCategory: 'Endpoint' as const })),
        ...reportData.rateLimitFindings.map(f => ({ ...f, findingCategory: 'RateLimit' as const })),
        ...reportData.loggingFindings.map(f => ({ ...f, findingCategory: 'Logging' as const })),
        ...reportData.httpClientFindings.map(f => ({ ...f, findingCategory: 'HttpClient' as const })),
    ];

    if (allFindings.length > 0) {
        // Sort findings primarily by severity, then category, then file/package name
        allFindings.sort((a, b) => {
            const severityA = getSeverityInfo(a.severity || a.maxSeverity || 'None').sortKey;
            const severityB = getSeverityInfo(b.severity || b.maxSeverity || 'None').sortKey;
            if (severityA !== severityB) return severityA - severityB;

            if (a.findingCategory !== b.findingCategory) return a.findingCategory.localeCompare(b.findingCategory);
            
            // Use file for most, package name for deps
            const nameA = a.file || a.name || ''; 
            const nameB = b.file || b.name || '';
            return nameA.localeCompare(nameB);
        });

        markdown += `| Severity | Category | Type | Location / Package | Message | Details |\n`;
        markdown += `|---|---|---|---|---|---|\n`;

        allFindings.forEach(finding => {
            const { emoji, sortKey } = getSeverityInfo(finding.severity || finding.maxSeverity || 'None');
            const severityText = finding.severity || finding.maxSeverity || 'None';
            let location = 'N/A';
            let message = finding.message || finding.type || 'No message';
            let details = finding.details || '';
            let findingType = finding.type || 'N/A';

            // Customize based on category
            switch (finding.findingCategory) {
                case 'Secret':
                    location = `${finding.file}:${finding.line}`;
                    message = `Pattern: ${finding.pattern}`;
                    break;
                case 'Dependency':
                    location = `${finding.name}@${finding.version}`;
                    findingType = 'Vulnerable Dependency';
                    if (finding.vulnerabilities && finding.vulnerabilities.length > 0) {
                        message = `${finding.vulnerabilities.length} known vulnerabilities. Highest Severity: ${finding.maxSeverity}.`;
                        details = finding.vulnerabilities.map((v: any) => `[${v.id}](${v.url || '#'}) (${v.severity || 'N/A'})`).join(', ');
                    } else if (finding.error) {
                        message = `Error checking OSV: ${finding.error}`;
                    } else {
                        message = 'No known vulnerabilities according to OSV.'; // Should ideally be filtered out earlier
                    }
                    break;
                case 'Config':
                    location = finding.file;
                    message = finding.description || `Key: ${finding.key}`; // Use description if available
                    details = finding.message; // Put the message in details
                    break;
                case 'Upload':
                case 'Endpoint':
                case 'Logging':
                case 'HttpClient':
                    location = `${finding.file}:${finding.line}`;
                    // Use default message/details
                    break;
                case 'RateLimit': // Handle the new project-level finding
                    location = 'Project-Level';
                    findingType = finding.type;
                    message = finding.message; // Main message
                    details = finding.details || ''; // Details from the finding
                    break;
            }

            // Escape pipe characters for Markdown table
            location = location.replace(/\|/g, '\\|');
            findingType = findingType.replace(/\|/g, '\\|');
            message = message.replace(/\|/g, '\\|');
            details = details.replace(/\|/g, '\\|');

            markdown += `| ${emoji} ${severityText} | ${finding.findingCategory} | ${findingType} | ${location} | ${message} | ${details} |\n`;
        });

    } else {
        markdown += `*✅ No significant issues found!*\n`;
    }
    markdown += `\n`;

    // --- Info & Warnings --- 
    if (reportData.infoSecretFindings.length > 0 || reportData.gitignoreWarnings.length > 0) {
        markdown += `## 💡 Info & Config Warnings\n\n`;
        if (reportData.infoSecretFindings.length > 0) {
            markdown += `### Potential Secrets in .env Files\n`;
            reportData.infoSecretFindings.forEach(f => {
                markdown += `- **File:** ${f.file.replace(/\|/g, '\\|')} (Line: ${f.line}) - Type: ${f.type.replace(/\|/g, '\\|')}\n`;
            });
            markdown += `*Note: Ensure .env files are listed in your .gitignore and are not committed to version control.*\n\n`;
        }
        if (reportData.gitignoreWarnings.length > 0) {
            markdown += `### Configuration Warnings\n`;
            reportData.gitignoreWarnings.forEach(w => {
                markdown += `- ${w.message.replace(/\|/g, '\\|')}\n`;
            });
            markdown += `\n`;
        }
    }

    // --- AI Suggestions ---
    let apiKey = process.env.OPENAI_API_KEY;
    if (! apiKey){ // ollama dont need an API key but this field can't be none
        apiKey = 'YOUR_API_KEY_PLACEHOLDER';
    }
    const spinner = ora(`Generating AI suggestions (using API from ${url}/v1 with model: ${model})... `).start();
    try {
        const aiSuggestions = await generateAISuggestions(reportData, {baseURL: url + '/v1', apiKey: apiKey}, model);
        spinner.succeed('AI suggestions generated.');
        markdown += aiSuggestions; // Append the suggestions section
    } catch (error: any) {
        spinner.fail('AI suggestion generation failed.');
        markdown += `\n## AI Suggestions\n\n*Error generating suggestions: ${error.message}*\n`; // Append error message
    }

    return markdown;
} 