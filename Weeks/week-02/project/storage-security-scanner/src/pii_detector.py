import re
import boto3
import json
import argparse
import io
from typing import List, Dict
from datetime import datetime
from pathlib import Path
from rich.console import Console
from rich.table import Table
from rich import box
import PyPDF2  # type: ignore

console = Console()

# ─────────────────────────────────────────
#  PII Patterns
# ─────────────────────────────────────────
PII_PATTERNS = {
    'EMAIL':        (re.compile(r'\b[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Z|a-z]{2,}\b'), 'HIGH'),
    'US_SSN':       (re.compile(r'\b\d{3}-\d{2}-\d{4}\b'), 'CRITICAL'),
    'UK_NIN':       (re.compile(r'\b[A-Z]{2}\d{6}[A-D]\b'), 'CRITICAL'),
    'PHONE_US':     (re.compile(r'\b(\+1[-.\s]?)?\(?\d{3}\)?[-.\s]\d{3}[-.\s]\d{4}\b'), 'MEDIUM'),
    'CREDIT_CARD':  (re.compile(r'\b(?:4[0-9]{12}(?:[0-9]{3})?|5[1-5][0-9]{14}|3[47][0-9]{13})\b'), 'CRITICAL'),
    'AWS_KEY':      (re.compile(r'\bAKIA[0-9A-Z]{16}\b'), 'CRITICAL'),
    'PRIVATE_KEY':  (re.compile(r'-----BEGIN (RSA |EC )?PRIVATE KEY-----'), 'CRITICAL'),
    'IP_ADDRESS':   (re.compile(r'\b(?:10|172\.(?:1[6-9]|2[0-9]|3[01])|192\.168)\.\d{1,3}\.\d{1,3}\b'), 'LOW'),
    'FULL_NAME':    (re.compile(r'\b[A-Z][a-z]{1,20}\s[A-Z][a-z]{1,20}(?:\s[A-Z][a-z]{1,20})?\b'), 'MEDIUM'),
    'DATE_OF_BIRTH':(re.compile(
                        r'\b(?:'
                        r'\d{2}[\/\-\.]\d{2}[\/\-\.]\d{4}'
                        r'|\d{4}[\/\-\.]\d{2}[\/\-\.]\d{2}'
                        r'|(?:0?[1-9]|[12][0-9]|3[01])\s'
                        r'(?:Jan|Feb|Mar|Apr|May|Jun|Jul|Aug|Sep|Oct|Nov|Dec)[a-z]*'
                        r'\s\d{4}'
                        r')\b'), 'HIGH'),
}

BINARY_EXTENSIONS = {'.jpg', '.jpeg', '.png', '.gif', '.zip', '.gz', '.tar', '.mp4', '.exe', '.bin'}

SEVERITY_ORDER = {'CRITICAL': 0, 'HIGH': 1, 'MEDIUM': 2, 'LOW': 3}


# ─────────────────────────────────────────
#  Core Scanner
# ─────────────────────────────────────────
def scan_bucket_for_pii(bucket_name: str, max_objects: int = 10,
                         max_bytes_per_object: int = 102400) -> List[Dict]:
    """Sample objects from a bucket and scan for PII patterns."""
    s3 = boto3.client('s3')
    findings = []

    try:
        objects = s3.list_objects_v2(Bucket=bucket_name, MaxKeys=max_objects)

        for obj in objects.get('Contents', []):
            key = obj['Key']
            size_kb = round(obj.get('Size', 0) / 1024, 1)

            # Determine how to handle this file type
            if key.lower().endswith('.pdf'):
                console.print(f"    Scanning PDF: [dim]{key}[/dim] ({size_kb} KB)")
                try:
                    raw = s3.get_object(Bucket=bucket_name, Key=key)['Body'].read(max_bytes_per_object)
                    content = _extract_pdf_text(raw)
                    if not content.strip():
                        console.print(f"    [dim]Skipping unreadable or empty PDF: {key}[/dim]")
                        continue
                except Exception as e:
                    console.print(f"    [yellow][!] Could not read PDF {key}: {e}[/yellow]")
                    continue

            elif any(key.lower().endswith(ext) for ext in BINARY_EXTENSIONS):
                console.print(f"    [dim]Skipping binary file: {key}[/dim]")
                continue

            else:
                console.print(f"    Scanning object: [dim]{key}[/dim] ({size_kb} KB)")
                try:
                    raw = s3.get_object(Bucket=bucket_name, Key=key)['Body'].read(max_bytes_per_object)
                    content = raw.decode('utf-8', errors='ignore')
                except Exception as e:
                    console.print(f"    [yellow][!] Could not read object {key}: {e}[/yellow]")
                    continue

            # Run PII patterns against extracted content
            for pii_type, (pattern, severity) in PII_PATTERNS.items():
                matches = pattern.findall(content)
                if matches:
                    findings.append({
                        'bucket':      bucket_name,
                        'object_key':  key,
                        'pii_type':    pii_type,
                        'severity':    severity,
                        'match_count': len(matches),
                        'sample':      _mask(str(matches[0]))
                    })

    except Exception as e:
        console.print(f"  [red][!] Could not scan {bucket_name} for PII: {e}[/red]")

    return findings


def scan_all_buckets_for_pii(profile: str = None, max_objects: int = 10,
                               max_bytes: int = 102400) -> Dict[str, List[Dict]]:
    """Scan all accessible S3 buckets for PII."""
    session = boto3.Session(profile_name=profile) if profile else boto3.Session()
    s3 = session.client('s3')

    buckets = s3.list_buckets().get('Buckets', [])
    all_results = {}

    for bucket in buckets:
        name = bucket['Name']
        console.print(f"\n  [cyan]Scanning bucket:[/cyan] {name}")
        findings = scan_bucket_for_pii(name, max_objects, max_bytes)
        all_results[name] = findings

    return all_results


# ─────────────────────────────────────────
#  Helpers
# ─────────────────────────────────────────
def _extract_pdf_text(pdf_bytes: bytes) -> str:
    """Extract plain text from a PDF file's raw bytes."""
    try:
        reader = PyPDF2.PdfReader(io.BytesIO(pdf_bytes))
        return ' '.join(page.extract_text() or '' for page in reader.pages)
    except Exception as e:
        console.print(f"    [yellow][!] PDF text extraction failed: {e}[/yellow]")
        return ''


def _mask(value: str) -> str:
    """Mask most characters for safe display in reports."""
    if len(value) <= 4:
        return '****'
    return value[:2] + '*' * (len(value) - 4) + value[-2:]


# ─────────────────────────────────────────
#  Output — Console Table
# ─────────────────────────────────────────
def print_findings_table(all_results: Dict[str, List[Dict]]):
    all_findings = [f for findings in all_results.values() for f in findings]

    if not all_findings:
        console.print("\n[green]✅ No PII detected across scanned buckets.[/green]")
        return

    table = Table(title="PII Detection Findings", box=box.ROUNDED, show_lines=True)
    table.add_column("Severity",  style="bold", width=10)
    table.add_column("Bucket",    width=30)
    table.add_column("Object",    width=25)
    table.add_column("PII Type",  width=15)
    table.add_column("Matches",   width=8)
    table.add_column("Sample",    width=20)

    severity_styles = {
        'CRITICAL': 'red',
        'HIGH':     'orange3',
        'MEDIUM':   'yellow',
        'LOW':      'green'
    }

    sorted_findings = sorted(all_findings, key=lambda x: SEVERITY_ORDER.get(x['severity'], 9))

    for f in sorted_findings:
        style = severity_styles.get(f['severity'], 'white')
        table.add_row(
            f"[{style}]{f['severity']}[/{style}]",
            f['bucket'],
            f['object_key'],
            f['pii_type'],
            str(f['match_count']),
            f['sample']
        )

    console.print(table)


# ─────────────────────────────────────────
#  Output — JSON Report
# ─────────────────────────────────────────
def generate_report(all_results: Dict[str, List[Dict]], output_dir: str = 'reports') -> dict:
    Path(output_dir).mkdir(exist_ok=True)
    timestamp = datetime.utcnow().strftime('%Y-%m-%d_%H-%M-%S')

    all_findings = [f for findings in all_results.values() for f in findings]

    report = {
        'report_metadata': {
            'timestamp':              datetime.utcnow().isoformat(),
            'tool':                   'S3 PII Detector',
            'total_buckets_scanned':  len(all_results),
            'total_objects_with_pii': len({f['object_key'] for f in all_findings}),
        },
        'summary': {
            'total_findings': len(all_findings),
            'critical':       sum(1 for f in all_findings if f['severity'] == 'CRITICAL'),
            'high':           sum(1 for f in all_findings if f['severity'] == 'HIGH'),
            'medium':         sum(1 for f in all_findings if f['severity'] == 'MEDIUM'),
            'low':            sum(1 for f in all_findings if f['severity'] == 'LOW'),
        },
        'findings_by_bucket': {
            bucket: sorted(findings, key=lambda x: SEVERITY_ORDER.get(x['severity'], 9))
            for bucket, findings in all_results.items()
            if findings
        }
    }

    json_path = f"{output_dir}/{timestamp}-pii-scan.json"
    with open(json_path, 'w') as f:
        json.dump(report, f, indent=2)

    console.print(f"\n[+] JSON report saved: [green]{json_path}[/green]")
    return report


# ─────────────────────────────────────────
#  Entry Point
# ─────────────────────────────────────────
def main():
    parser = argparse.ArgumentParser(description='S3 PII Detector')
    parser.add_argument('--bucket',      default=None,   help='Scan a specific bucket only (omit to scan all)')
    parser.add_argument('--profile',     default=None,   help='AWS profile to use')
    parser.add_argument('--max-objects', default=10,     type=int, help='Max objects to sample per bucket (default: 10)')
    parser.add_argument('--max-bytes',   default=102400, type=int, help='Max bytes to read per object (default: 100KB)')
    parser.add_argument('--output',      default='reports', help='Output directory for reports')
    args = parser.parse_args()

    console.print("\n[bold blue]🔍 S3 PII Detector[/bold blue]\n")
    console.print(f"Max objects per bucket: [yellow]{args.max_objects}[/yellow]")
    console.print(f"Max bytes per object:   [yellow]{args.max_bytes}[/yellow]\n")

    if args.bucket:
        console.print(f"[*] Scanning bucket: [cyan]{args.bucket}[/cyan]")
        findings = scan_bucket_for_pii(args.bucket, args.max_objects, args.max_bytes)
        all_results = {args.bucket: findings}
    else:
        console.print("[*] Scanning all accessible S3 buckets...", style="cyan")
        all_results = scan_all_buckets_for_pii(args.profile, args.max_objects, args.max_bytes)

    print_findings_table(all_results)
    report = generate_report(all_results, args.output)

    console.print(f"\n[bold green]✅ PII Scan Complete![/bold green]")
    console.print(f"   Buckets scanned:        [white]{report['report_metadata']['total_buckets_scanned']}[/white]")
    console.print(f"   Objects with PII:       [white]{report['report_metadata']['total_objects_with_pii']}[/white]")
    console.print(f"   Critical:               [red]{report['summary']['critical']}[/red]")
    console.print(f"   High:                   [orange3]{report['summary']['high']}[/orange3]")
    console.print(f"   Medium:                 [yellow]{report['summary']['medium']}[/yellow]")
    console.print(f"   Low:                    [green]{report['summary']['low']}[/green]")


if __name__ == '__main__':
    main()