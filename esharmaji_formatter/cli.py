#!/usr/bin/env python3

"""
Esharmaji Cyber Formatter
=========================

Auto-detect and format security scanner outputs into human-readable CSV, PDF, HTML, Markdown, or Text reports.

Supported Tools:
- Trivy
- Semgrep
- Detect-Secrets (baseline JSON and audit output)
- Gitleaks
- CloudSploit
- SonarQube

Author: cybersharmaji
"""

import os
import json
import csv
import argparse
import re
from pathlib import Path
from collections import Counter
from rich.console import Console
from rich.table import Table
from rich import box
from fpdf import FPDF
from jinja2 import Template

console = Console()

def detect_tool(file_path, debug=False):
    try:
        with open(file_path, 'r', encoding='utf-8', errors='ignore') as f:
            contents = f.read()
            f.seek(0)
            try:
                data = json.load(f)
            except json.JSONDecodeError:
                data = None

            if debug:
                console.print(f"[yellow]Data type:[/yellow] {type(data)}")

            if isinstance(data, dict):
                # Semgrep
                if isinstance(data.get("results"), list) and data["results"] and "check_id" in data["results"][0]:
                    if debug: print("Matched: Semgrep")
                    return "semgrep"

                # Trivy
                if isinstance(data.get("Results"), list) and data["Results"] and "Vulnerabilities" in data["Results"][0]:
                    if debug: print("Matched: Trivy")
                    return "trivy"

                # Detect-Secrets
                if "plugins_used" in data and "results" in data:
                    if debug: print("Matched: Detect-Secrets (JSON)")
                    return "detect-secrets"

                # SonarQube
                if isinstance(data.get("issues"), list) and data["issues"] and "severity" in data["issues"][0]:
                    if debug: print("Matched: SonarQube")
                    return "sonarqube"

            elif isinstance(data, list):
                # Gitleaks
                for i, item in enumerate(data):
                    if isinstance(item, dict) and "rule" in item and ("secret" in item or "match" in item):
                        if debug: print(f"Matched: Gitleaks at index {i}")
                        return "gitleaks"

                # CloudSploit
                for i, item in enumerate(data):
                    if isinstance(item, dict) and "provider" in item and "service" in item and ("severity" in item or "message" in item):
                        if debug: print(f"Matched: CloudSploit at index {i}")
                        return "cloudsploit"

            # Detect-Secrets Audit (text fallback)
            if 'Secret:' in contents and 'Filename:' in contents and 'Secret Type:' in contents:
                if debug: print("Matched: Detect-Secrets Audit")
                return "detect-secrets-audit"

    except Exception as e:
        if debug:
            print(f"[DEBUG] Error reading file: {e}")
    if debug:
        print("No match found.")
    return None

# Formatters for each supported tool

def format_trivy(input_file, output, output_type):
    with open(input_file) as f:
        data = json.load(f)
    headers = ["Target", "Vulnerability ID", "Pkg Name", "Installed Version", "Fixed Version", "Severity", "Title", "Primary URL"]
    rows = []
    for result in data.get("Results", []):
        target = result.get("Target", "")
        for vuln in result.get("Vulnerabilities", []):
            rows.append([
                target,
                vuln.get("VulnerabilityID", ""),
                vuln.get("PkgName", ""),
                vuln.get("InstalledVersion", ""),
                vuln.get("FixedVersion", ""),
                vuln.get("Severity", ""),
                vuln.get("Title", ""),
                vuln.get("PrimaryURL", "")
            ])
    write_output(output, output_type, headers, rows)

def format_semgrep(input_file, output, output_type):
    with open(input_file) as f:
        data = json.load(f)
    headers = ["Check ID", "File", "Start Line", "End Line", "Severity", "Message"]
    rows = []
    for result in data.get("results", []):
        rows.append([
            result.get("check_id", ""),
            result.get("path", ""),
            result.get("start", {}).get("line", ""),
            result.get("end", {}).get("line", ""),
            result.get("extra", {}).get("severity", ""),
            result.get("extra", {}).get("message", "")
        ])
    write_output(output, output_type, headers, rows)

def format_detect_secrets(input_file, output, output_type):
    with open(input_file) as f:
        data = json.load(f)
    headers = ["Filename", "Secret Type", "Line Number", "Hashed Secret"]
    rows = []
    for file_path, secrets in data.get("results", {}).items():
        for secret in secrets:
            rows.append([
                file_path,
                secret.get("type", ""),
                secret.get("line_number", ""),
                secret.get("hashed_secret", "")
            ])
    write_output(output, output_type, headers, rows)

def format_detect_secrets_audit(input_file, output, output_type):
    headers = ["Secret ID", "Filename", "Secret Type", "Line Number", "Hashed Secret"]
    rows = []
    secret_id = 0
    filename = secret_type = line_number = hashed_secret = None
    with open(input_file, 'r', encoding='utf-8', errors='ignore') as f:
        for line in f:
            line = line.strip()
            if line.startswith("Secret:"):
                secret_id += 1
            elif line.startswith("Filename:"):
                filename = line.split("Filename:")[1].strip()
            elif line.startswith("Secret Type:"):
                secret_type = line.split("Secret Type:")[1].strip()
            elif re.match(r"^\d+:", line):
                try:
                    json_line = ":".join(line.split(":")[1:]).strip().rstrip(",")
                    json_obj = json.loads(json_line)
                    line_number = json_obj.get("line_number", "")
                    hashed_secret = json_obj.get("hashed_secret", "")
                except:
                    continue
            if filename and secret_type and line_number and hashed_secret:
                rows.append([
                    f"Secret {secret_id}", filename, secret_type, line_number, hashed_secret
                ])
                filename = secret_type = line_number = hashed_secret = None
    write_output(output, output_type, headers, rows)

def format_gitleaks(input_file, output, output_type):
    with open(input_file) as f:
        data = json.load(f)
    headers = ["Rule ID", "File", "Line", "Secret", "Commit", "Author", "Date"]
    rows = []
    for item in data:
        rows.append([
            item.get("rule", ""),
            item.get("file", ""),
            item.get("line", ""),
            item.get("secret", ""),
            item.get("commit", ""),
            item.get("author", ""),
            item.get("date", "")
        ])
    write_output(output, output_type, headers, rows)

def format_cloudsploit(input_file, output, output_type):
    with open(input_file) as f:
        data = json.load(f)
    headers = ["Provider", "Service", "Region", "Severity", "Message", "Description"]
    rows = []
    for finding in data:
        rows.append([
            finding.get("provider", ""),
            finding.get("service", ""),
            finding.get("region", ""),
            finding.get("severity", ""),
            finding.get("message", ""),
            finding.get("description", "")
        ])
    write_output(output, output_type, headers, rows)

def format_sonarqube(input_file, output, output_type):
    with open(input_file) as f:
        data = json.load(f)
    headers = ["Issue Type", "Component", "Message", "Severity", "Line", "Rule"]
    rows = []
    for issue in data.get("issues", []):
        rows.append([
            issue.get("type", ""),
            issue.get("component", ""),
            issue.get("message", ""),
            issue.get("severity", ""),
            issue.get("line", ""),
            issue.get("rule", "")
        ])
    write_output(output, output_type, headers, rows)

formatters = {
    "trivy": format_trivy,
    "semgrep": format_semgrep,
    "detect-secrets": format_detect_secrets,
    "detect-secrets-audit": format_detect_secrets_audit,
    "gitleaks": format_gitleaks,
    "cloudsploit": format_cloudsploit,
    "sonarqube": format_sonarqube
}
# HTML output with charts

def write_output(output, output_type, headers, rows):
    if output_type == "html":
        chart_labels = []
        chart_data = []
        if len(headers) >= 2:
            counts = Counter([row[1] for row in rows])
            chart_labels = list(counts.keys())
            chart_data = list(counts.values())

        html_template = Template("""
        <html><head><meta charset='UTF-8'>
        <script src="https://cdn.jsdelivr.net/npm/chart.js"></script>
        <style>
        body { font-family: Arial, sans-serif; padding: 20px; }
        h2 { color: #2c3e50; }
        table { border-collapse: collapse; width: 100%; margin-top: 20px; }
        th, td { border: 1px solid #ddd; padding: 8px; text-align: left; }
        th { background-color: #f4f4f4; color: #333; }
        tr:nth-child(even) { background-color: #f9f9f9; }
        canvas { margin-top: 30px; }
        </style></head><body>
        <h2>Esharmaji Cyber Formatter Report</h2>

        {% if chart_labels %}
        <h3>Summary Chart ({{ headers[1] }})</h3>
        <canvas id="chart" width="400" height="200"></canvas>
        <script>
        const ctx = document.getElementById('chart').getContext('2d');
        new Chart(ctx, {
            type: 'bar',
            data: {
                labels: {{ chart_labels | tojson }},
                datasets: [{
                    label: 'Count',
                    data: {{ chart_data | tojson }},
                    backgroundColor: ['#3498db','#2ecc71','#f39c12','#e74c3c','#8e44ad']
                }]
            },
            options: {responsive: true, plugins: {legend: {display: false}}}
        });
        </script>
        {% endif %}

        <table>
            <thead><tr>{% for h in headers %}<th>{{ h }}</th>{% endfor %}</tr></thead>
            <tbody>
                {% for row in rows %}
                <tr>{% for r in row %}<td>{{ r }}</td>{% endfor %}</tr>
                {% endfor %}
            </tbody>
        </table>
        </body></html>
        """)
        html = html_template.render(headers=headers, rows=rows, chart_labels=chart_labels, chart_data=chart_data)
        with open(output, 'w', encoding='utf-8') as htmlfile:
            htmlfile.write(html)
        console.print(f"[green]HTML saved with chart:[/green] {output}")

    elif output_type == "csv":
        with open(output, 'w', encoding='utf-8-sig', newline='') as f:
            writer = csv.writer(f)
            writer.writerow(headers)
            writer.writerows(rows)
        console.print(f"[green]CSV saved:[/green] {output}")

    else:
        table = Table(show_header=True, header_style="bold magenta", box=box.SIMPLE)
        for h in headers:
            table.add_column(h)
        for row in rows:
            table.add_row(*[str(r) for r in row])
        with open(output, 'w') as f:
            file_console = Console(file=f)
            file_console.print(table)
        console.print(f"[green]{output_type.upper()} saved:[/green] {output}")



def main():
    parser = argparse.ArgumentParser(description="Esharmaji Cyber Formatter")
    parser.add_argument("input", help="Input scan report file or folder")
    parser.add_argument("--out", help="Output file name or folder")
    parser.add_argument("--type", help="Output format", choices=["csv", "text", "md", "pdf", "html"], default="csv")
    parser.add_argument("--debug", help="Enable debug mode", action="store_true")
    args = parser.parse_args()

    inputs = []
    if os.path.isdir(args.input):
        inputs = [str(p) for p in Path(args.input).glob("*.json")]
    else:
        inputs = [args.input]

    for input_path in inputs:
        tool = detect_tool(input_path, debug=args.debug)
        if not tool:
            console.print(f"[red]Could not detect tool type for {input_path}[/red]")
            continue

        output_base = args.out or Path(input_path).with_suffix(f".{args.type}")
        if os.path.isdir(args.out or ""):
            output = Path(args.out) / Path(input_path).with_suffix(f".{args.type}").name
        else:
            output = output_base

        console.print(f"[blue]Detected tool:[/blue] {tool} → {input_path}")
        formatter = formatters.get(tool)
        if formatter:
            formatter(input_path, output, args.type)
        else:
            console.print(f"[red]No formatter available for {tool}[/red]")

if __name__ == "__main__":
    main()
