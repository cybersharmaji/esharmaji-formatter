#!/usr/bin/env python3

"""
Esharmaji Cyber Formatter
=========================

🧠 Description:
    This tool auto-detects and formats scan outputs from tools like Trivy, Semgrep, Detect-Secrets,
    Gitleaks, Grype, SARIF, SonarQube, CycloneDX, OWASP Dependency Check, CloudSploit, etc.

📦 Usage:
    python3 esharmaji_formatter/cli.py path/to/report.json --type csv
    python3 esharmaji_formatter/cli.py scan.sarif --type pdf --out report.pdf

🔧 Output Formats:
    --type csv    → Comma-separated values
    --type text   → Plain text (ASCII table)
    --type md     → Markdown table
    --type pdf    → PDF report
    --type html   → HTML dashboard

💡 Example:
    esharmaji-formatter trivy-results.json --type html

Author: cybersharmaji
"""

import os
import json
import csv
import argparse
from pathlib import Path
from rich.console import Console
from rich.table import Table
from rich import box
from markdownify import markdownify as md
from fpdf import FPDF
from jinja2 import Template

console = Console()

SUPPORTED_TOOLS = ["trivy", "semgrep", "detect-secrets", "sonarqube", "sarif", "grype", "gitleaks", "owasp-depcheck", "cyclonedx", "cloudsploit"]

# ...[Detect & Formatter functions from original code remain unchanged]...

# ------------------ Extended Output Writers ------------------
def write_output(output, output_type, headers, rows):
    if output_type == "csv":
        with open(output, 'w', newline='') as csvfile:
            writer = csv.writer(csvfile)
            writer.writerow(headers)
            writer.writerows(rows)
        console.print(f"[green]CSV report saved to:[/green] {output}")

    elif output_type == "text":
        table = Table(show_header=True, header_style="bold magenta", box=box.SIMPLE)
        for h in headers:
            table.add_column(h)
        for row in rows:
            table.add_row(*[str(r) for r in row])
        with open(output, 'w') as txtfile:
            file_console = Console(file=txtfile)
            file_console.print(table)
        console.print(f"[green]Text report saved to:[/green] {output}")

    elif output_type == "md":
        with open(output, 'w') as mdfile:
            mdfile.write("| " + " | ".join(headers) + " |\n")
            mdfile.write("|" + "---|" * len(headers) + "\n")
            for row in rows:
                mdfile.write("| " + " | ".join(map(str, row)) + " |\n")
        console.print(f"[green]Markdown report saved to:[/green] {output}")

    elif output_type == "pdf":
        pdf = FPDF()
        pdf.add_page()
        pdf.set_font("Arial", size=10)
        col_width = 190 // len(headers)
        row_height = 10
        for header in headers:
            pdf.cell(col_width, row_height, header, border=1)
        pdf.ln(row_height)
        for row in rows:
            for item in row:
                pdf.cell(col_width, row_height, str(item), border=1)
            pdf.ln(row_height)
        pdf.output(output)
        console.print(f"[green]PDF report saved to:[/green] {output}")

    elif output_type == "html":
        html_template = Template("""
        <html><head><style>
        table {border-collapse: collapse; width: 100%; font-family: Arial;}
        th, td {border: 1px solid #ddd; padding: 8px;}
        th {background-color: #f2f2f2; text-align: left;}
        </style></head><body>
        <h2>Formatted Report</h2>
        <table>
            <thead>
                <tr>{% for h in headers %}<th>{{ h }}</th>{% endfor %}</tr>
            </thead>
            <tbody>
                {% for row in rows %}<tr>{% for r in row %}<td>{{ r }}</td>{% endfor %}</tr>{% endfor %}
            </tbody>
        </table>
        </body></html>
        """)
        html = html_template.render(headers=headers, rows=rows)
        with open(output, 'w') as htmlfile:
            htmlfile.write(html)
        console.print(f"[green]HTML report saved to:[/green] {output}")

# ------------------ CLI Entry ------------------
def main():
    parser = argparse.ArgumentParser(description="Esharmaji Cyber Formatter - Format security scan outputs into human-readable reports")
    parser.add_argument("input", help="Input file (report JSON/TXT/etc)")
    parser.add_argument("--out", help="Output file name", required=False)
    parser.add_argument("--type", help="Output format: csv, text, md, pdf, html", choices=["csv", "text", "md", "pdf", "html"], default="csv")
    args = parser.parse_args()

    tool = detect_tool(args.input)
    if not tool:
        console.print("[red]Could not detect tool type from report! Supported: Trivy, Semgrep, Detect-Secrets, etc.[/red]")
        exit(1)

    output = args.out or Path(args.input).with_suffix(f".{args.type}")
    console.print(f"[blue]Detected tool:[/blue] {tool}")

    formatter = formatters.get(tool)
    formatter(args.input, output, args.type)

if __name__ == "__main__":
    main()
