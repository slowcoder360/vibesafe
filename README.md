# VibeSafe ✨🛡️

A CLI tool to scan your codebase for security vibes.

VibeSafe helps developers quickly check their projects for common security issues like exposed secrets, outdated dependencies with known vulnerabilities (CVEs), and generates helpful reports.

![License: MIT](https://img.shields.io/badge/license-MIT-blue.svg)


## ✨ Features

- 🔐 **Secret Scanning**  
  Flags AWS keys, JWTs, SSH keys, high-entropy strings, and secrets in `.env` files.

- 🛡️ **Secure Package Installation** (`vibesafe install`)  
  Helps prevent slopsquatting & typosquatting by checking package trustworthiness before installing.

- 📦 **Dependency Vulnerability Detection**  
  Checks `package.json` dependencies against the [OSV.dev](https://osv.dev) vulnerability database. *(Direct deps only for now — lockfile support coming soon).*

- ⚙️ **Insecure Config Detection**  
  Scans JSON/YAML for flags like `DEBUG=true`, `devMode`, permissive CORS, etc.

- 🌐 **HTTP Client Scan**  
  Detects missing timeouts or abort controllers in `axios`, `fetch`, `got`, etc.

- 📤 **Upload Validation Check**  
  Warns on lack of file size/type checks in `multer`, `formidable`, etc.

- 🔎 **Exposed Endpoint Detection**  
  Flags risky endpoints like `/admin`, `/debug`, or `/metrics`, including for **Next.js API routes**.

- 🚫 **Missing Rate Limiting (Heuristic)**  
  Warns if your project has API routes but no known rate-limit package installed.

- 🪵 **Improper Logging Patterns**  
  Finds logs that may leak sensitive info or log full error stacks unsafely.

- 📄 **Multi-format Output**  
  Console, JSON (`--output`), or Markdown reports (`--report`).

- 🧠 **AI-Powered Fix Suggestions (Optional)**  
  Add an OpenAI API key for smart recommendations in Markdown reports.

- 🎯 **Focus on Critical Issues**  
  Use `--high-only` to trim noise.

- 🙈 **Custom Ignores**  
  Exclude files using `.vibesafeignore`, just like `.gitignore`.


## 📦 Installation

```bash
npm install -g vibesafe 
```

*(Note: Currently, for local development, use `npm link` after building)*

## 🚀 Usage

**Basic Scan (Current Directory):**

```bash
vibesafe scan
```

**Scan a Specific Directory:**

```bash
vibesafe scan ./path/to/your/project
```

**Output to JSON:**

```bash
vibesafe scan -o scan-results.json
```

**Generate Markdown Report:**

To generate a Markdown report, use the `-r` or `--report` flag. You can optionally provide a filename. If no filename is given, it defaults to `VIBESAFE-REPORT.md` in the scanned directory.

*With a specific filename:*
```bash
vibesafe scan -r scan-report.md
```

*Using the default filename (`VIBESAFE-REPORT.md`):*
```bash
vibesafe scan -r
# or
vibesafe scan --report 
```

*Using a local llm host for report (the llm host must support OpenAI API)
```bash
 # example with ollama at local host with default ollama port
 vibesafe scan --url http://127.0.0.1:11434 --model gemma3:27b-it-q8_0
```

if --url flag is not specified the report will be done by OpenAI (you will need an OpenAI API Key, see below)

**Generate AI Report from OpenAI (Requires API Key):**

To generate fix suggestions in the Markdown report, you need an OpenAI API key.

1.  Create a `.env` file in the root of the directory where you run `vibesafe` (or in the project root if running locally during development).
2.  Add your key to the `.env` file:
    ```
    OPENAI_API_KEY=sk-YourActualOpenAIKeyHere
    ```
3.  Run the scan with the report flag:
    ```bash
vibesafe scan -r ai-report.md
    ```

**Show Only High/Critical Issues:**

```bash
vibesafe scan --high-only
```

## 🛡️ Secure Package Installation: `vibesafe install`

VibeSafe now includes a command to help you install npm packages more safely, protecting against typosquatting and other suspicious packages.

**Basic Usage:**

Use `vibesafe install` (or its alias `vibesafe i`) just like you would use `npm install`:

```bash
vibesafe install <package-name>
# Example
vibesafe install express
```

**How it Works:**

Before installing, `vibesafe install` performs several heuristic checks on the package(s) you want to install:

*   **Package Age:** Flags very new packages (e.g., published within the last 30 days).
*   **Download Volume:** Flags packages with very low download counts.
*   **README Presence:** Checks for a missing or placeholder README file.
*   **License:** Verifies if a license is specified.
*   **Repository/Homepage:** Checks for a linked code repository or homepage.

**User Confirmation:**

If any of these checks raise a warning, VibeSafe will list the concerns and ask for your confirmation before proceeding with the installation:

```shell
$ vibesafe install some-new-package
[vibesafe] Processing package "some-new-package" (1 of 1)...
[vibesafe] Fetching metadata for "some-new-package"...
[vibesafe] Successfully fetched metadata for "some-new-package".
  Created: <date>
[vibesafe] ⚠ Found 2 heuristic warning(s) for "some-new-package":
  - Package "some-new-package" was published recently... (Severity: Medium)
    Details: Published 0 days ago (threshold: 30 days)
  - Package "some-new-package" has a placeholder README... (Severity: Low)
    Details: ...
Are you sure you want to install "some-new-package"? [y/N]
```

*   Enter `y` or `yes` to proceed despite warnings.
*   Enter `n` or press Enter to abort the installation.

**Automatic Yes (for CI/Scripts):**

Use the `--yes` flag to automatically accept warnings and proceed with installation. This is useful in non-interactive environments.

```bash
vibesafe install <package-name> --yes
```
If `--yes` is not used in a non-interactive environment (e.g., a script without a TTY), VibeSafe will abort installation if any warnings are found.

**Installing Multiple Packages:**

You can specify multiple packages to install in one command. VibeSafe will process them sequentially:

```bash
vibesafe install packageA packageB packageC
```
If an issue is found with one package and you choose to abort, subsequent packages in the list will not be processed.

**Passing Flags to npm (e.g., `--save-dev`):**

If you need to pass additional arguments directly to the `npm install` command (like `--save-dev`, `--legacy-peer-deps`, etc.), use the `--` separator after your package names and before the npm flags:

```bash
vibesafe install <package-name> -- --save-dev
vibesafe install packageA packageB -- --save-dev --legacy-peer-deps
```

### Future Enhancements for `vibesafe install` (TODO)

We plan to enhance `vibesafe install` with more advanced security features:

*   **Typosquatting & Name Similarity Detection:**
    *   Detect package names that are very similar to popular packages (e.g., using Levenshtein distance).
    *   Suggest correct package names if a typo is suspected (e.g., "Did you mean `express`?").
*   **Malicious Package Database Check:**
    *   Integrate with services like OSV.dev to check if a package version is known to be malicious.
*   **Installation Script Warnings:**
    *   Inspect package manifests for `preinstall`/`postinstall` scripts and warn the user.
*   **Configurable Rules:**
    *   Allow users to customize thresholds for warnings (e.g., package age, download counts) via a configuration file.

## 🛑📁 Ignoring Files (.vibesafeignore)

Create a `.vibesafeignore` file in the root of the directory being scanned. Add file paths or glob patterns (one per line) to exclude them from the scan. The syntax is the same as `.gitignore`.

**Example `.vibesafeignore**:

```
# Ignore all test data
test-data/

# Ignore a specific configuration file
config/legacy-secrets.conf

# Allow scanning a specific .env file if needed (overrides default info behavior)
# !.env.production 
```
## 🤝 Contributing

We welcome contributions from the community!

If you have an idea for a new scanner, a bug fix, or a way to make VibeSafe better, check out our [Contributing Guide](./CONTRIBUTING.md) to get started.

Whether you're submitting a pull request or opening an issue, we appreciate your help in making security tools more developer-friendly.

## 🧾 License

VibeSafe is open source software licensed under the [MIT License](./LICENSE).

You're free to use, modify, and distribute it — even commercially — as long as the original copyright
and license are included.

For questions or commercial partnership inquiries, contact **vibesafepackage@gmail.com**.

---

## 📛 Trademark Notice

**VibeSafe™** is a trademark of Secret Society LLC.  
Use of the name "VibeSafe" for derivative tools, competing products, or commercial services is **not permitted without prior written consent.**

You are free to fork or build upon this code under the [MIT License](./LICENSE), but please use a different name and branding for public or commercial distributions.
