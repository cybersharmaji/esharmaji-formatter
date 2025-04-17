# 🧠 Esharmaji Cyber Formatter

**Esharmaji Cyber Formatter** is a no-nonsense, pluggable CLI tool built for cybersecurity professionals, bug bounty hunters, and DevSecOps engineers.

It **automatically detects and formats security scan outputs** from open-source tools like Trivy, Semgrep, SARIF, Gitleaks, and more — into clean, readable **CSV**, **Markdown**, **Text**, **PDF**, or **HTML** reports.

---

## 🚀 Features

✅ **Auto-detects** report format  
✅ Supports **10+ tools** out-of-the-box  
✅ Converts JSON clutter into **beautiful readable reports**  
✅ Output formats: `csv`, `text`, `md`, `pdf`, `html`  
✅ Lightweight & terminal-native (Kali/Parrot ready)  
✅ Built by a hacker, for hackers 🧙‍♂️

---

## 📦 Supported Tools

| Tool               | Format      | Notes |
|--------------------|-------------|-------|
| Trivy              | JSON        | fs/image scans |
| Semgrep            | JSON        | SAST analysis |
| Detect-Secrets     | JSON        | Secrets detection |
| Gitleaks           | JSON        | Secrets in repos |
| SARIF              | JSON        | Static Analysis Format |
| Grype              | JSON        | SBOM & vuln scan |
| OWASP DepCheck     | JSON        | Java/Node package vulns |
| CycloneDX          | JSON        | SBOM components |
| CloudSploit        | JSON        | Cloud misconfigs |
| SonarQube          | JSON        | Code quality/vulns |

---

## 🛠️ Installation

### 🔧 Option 1: Local Install

git clone https://github.com/cybersharmaji/esharmaji-formatter.git
cd esharmaji-formatter
pip install .

### 🐳 Option 2: Coming Soon – Docker Support

### 🧪 Usage

esharmaji-formatter <path-to-scan.json> --type <output-format> --out <optional-output-file>

### 🎯 Examples

Basic CSV report from a Trivy scan:

➡️esharmaji-formatter trivy-results.json --type csv

Generate a PDF report from SARIF format:

➡️esharmaji-formatter scan.sarif --type pdf --out report.pdf

Create a Markdown table from Semgrep output:

➡️esharmaji-formatter semgrep-output.json --type md

Generate an HTML dashboard from Detect-Secrets:

➡️esharmaji-formatter secrets.json --type html --out secrets-report.html


### 🖨️ Output Formats

| Format   | Flag         | Description                                      |
|----------|--------------|--------------------------------------------------|
| CSV      | --type csv   | Comma-separated values for Excel or Sheets       |
| Text     | --type text  | Plain ASCII table for terminal use               |
| Markdown | --type md    | GitHub/GitLab-friendly markdown table            |
| PDF      | --type pdf   | Shareable and printable PDF report               |
| HTML     | --type html  | Styled, browser-based dashboard report           |


### 🔐 Ideal For
➡️Red teamers & pentesters
➡️DevSecOps engineers
➡️Security automation pipelines
➡️CI/CD integration
➡️HackerOne/Bugcrowd triaging

### 🧠 Author
Built with ❤️ by cybersharmaji/ethicalsharmaji

### 💬 For feedback, issues, or feature requests — raise an issue

### 📝 License
MIT — free for use, modification, and contribution.

### 📌 Roadmap
 ➡️Upload to PyPI for pip install esharmaji-formatter
 ➡️Add Docker support
 ➡️GitHub Actions integration
 ➡️Plugin system for custom formatters


