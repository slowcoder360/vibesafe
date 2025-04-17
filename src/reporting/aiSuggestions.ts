import OpenAI from 'openai';
import { SecretFinding } from '../scanners/secrets';
import { DependencyFinding } from '../scanners/dependencies';
import ora from 'ora';

// Initialize OpenAI client
// The constructor automatically looks for process.env.OPENAI_API_KEY
let openai: OpenAI | null = null;
try {
    // Only initialize if the key is present
    if (process.env.OPENAI_API_KEY && process.env.OPENAI_API_KEY !== 'YOUR_OPENAI_API_KEY_HERE') {
        openai = new OpenAI();
        console.log('OpenAI client initialized.'); // Log success
    } else {
        console.warn('OPENAI_API_KEY environment variable not set or is placeholder. AI suggestions will be skipped.');
    }
} catch (error: any) {
    console.error('Error initializing OpenAI client:', error.message);
}

interface ReportData {
    secretFindings: SecretFinding[];
    dependencyFindings: DependencyFinding[];
}

// Limit the amount of data sent to the LLM to manage cost/context window
const MAX_SECRETS_FOR_AI = 10;
const MAX_DEPS_FOR_AI = 15;

/**
 * Generates AI-powered fix suggestions based on findings.
 * @param reportData Object containing scan findings.
 * @returns A string containing formatted fix suggestions, or a placeholder if AI fails.
 */
export async function getAiFixSuggestions(reportData: ReportData): Promise<string> {
    if (!openai) {
        return '*AI suggestions skipped (OpenAI client not initialized or API key missing/placeholder).*';
    }

    // Prepare a summarized version of findings for the prompt
    const summarizedData = {
        secrets: reportData.secretFindings
            .slice(0, MAX_SECRETS_FOR_AI)
            .map(f => ({ file: f.file, line: f.line, type: f.type, severity: f.severity })), // Keep severity
        dependencies: reportData.dependencyFindings
            .filter(f => f.vulnerabilities.length > 0) // Only include deps with vulns
            .slice(0, MAX_DEPS_FOR_AI)
            .map(d => ({ name: d.name, version: d.version, maxSeverity: d.maxSeverity, cveIds: d.vulnerabilities.map(v => v.id).slice(0, 3) }))
    };

    // Only proceed if there are actual findings to report
    if (summarizedData.secrets.length === 0 && summarizedData.dependencies.length === 0) {
        return '*No significant issues found requiring AI suggestions.*';
    }

    const prompt = `
You are a helpful security assistant integrated into a tool called VibeSafe.
Given the following security findings from a code scan (JSON format), provide a concise, actionable list of fix suggestions in Markdown format.
Focus on the most impactful recommendations based on severity and type.
Keep suggestions brief and practical for a developer. Prioritize high/critical issues.
Structure the output as a numbered list.

Findings:
\`\`\`json
${JSON.stringify(summarizedData, null, 2)}
\`\`\`

Generate a numbered list of Markdown fix suggestions below:
`;

    const spinner = ora('Requesting AI fix suggestions from OpenAI (gpt-4o-mini)... ').start();
    try {
        const completion = await openai.chat.completions.create({
            model: 'gpt-4o-mini',
            messages: [
                { role: 'system', content: 'You are a helpful security assistant providing concise fix suggestions in Markdown format.' },
                { role: 'user', content: prompt }
            ],
            max_tokens: 350,
            temperature: 0.3,
            n: 1,
            stop: null,
        });

        const suggestions = completion.choices[0]?.message?.content?.trim();

        if (suggestions) {
            spinner.succeed('AI suggestions received.');
            // Basic validation/cleanup
            if (suggestions.startsWith('```markdown')) {
                return suggestions.substring(10, suggestions.length - 3).trim();
            }
            return suggestions;
        } else {
            spinner.warn('AI suggestion generation failed (empty response from API).');
            return '*AI suggestion generation failed (empty response).*';
        }

    } catch (error: any) {
        spinner.fail('OpenAI API request failed.');
        // Check for specific OpenAI errors if possible
        if (error instanceof OpenAI.APIError) {
            console.error(`Error calling OpenAI API: ${error.status} ${error.name} ${error.message}`);
            return `*AI suggestions failed due to an API error: ${error.name} (${error.message})*`;
        } else {
            console.error('Error calling OpenAI API:', error.message || error);
            return `*AI suggestions failed due to an unexpected error: ${error.message || error}*`;
        }
    }
}
 