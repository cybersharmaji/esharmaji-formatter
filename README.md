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

🧪 Usage
esharmaji-formatter <path-to-scan.json> --type <output-format> --out <optional-output-file>

## 🎯 Examples
esharmaji-formatter trivy-result.json --type csv
esharmaji-formatter scan.sarif --type pdf
esharmaji-formatter semgrep.json --type html --out semgrep_report.html

🖨️ Output Formats

Format | Flag | Use Case
csv | --type csv | Excel-friendly format
text | --type text | Terminal/ASCII table
md | --type md | Markdown for GitHub or docs
pdf | --type pdf | Offline report for sharing
html | --type html | Clean, styled dashboard view

🔐 Ideal For

Red teamers & pentesters
DevSecOps engineers
Security automation pipelines
CI/CD integration
HackerOne/Bugcrowd triaging

🧠 Author
Built with ❤️ by cybersharmaji/ethicalsharmaji
💬 For feedback, issues, or feature requests — raise an issue


