#!/usr/bin/env python3
import argparse
from rich.console import Console
from .bucket_checker import scan_all_buckets
from .pii_detector import scan_all_buckets_for_pii, scan_bucket_for_pii
from .reporter import generate_html_report, generate_json_report

console = Console()

def main():
    parser = argparse.ArgumentParser(description='S3 Storage Security Scanner')
    parser.add_argument('--profile', help='AWS profile name')
    parser.add_argument('--output',  default='reports')
    parser.add_argument('--bucket',  default=None, help='Scan a specific bucket only')
    parser.add_argument('--pii',     action='store_true', help='Enable PII scanning (slower)')
    args = parser.parse_args()

    console.print("\n[bold blue]🔒 S3 Storage Security Scanner[/bold blue]\n")

    # ── S3 misconfiguration scan ──
    console.print("[*] Scanning S3 buckets for misconfigurations...", style="cyan")
    results = scan_all_buckets(args.profile)

    # ── PII scan (optional, --pii flag required) ──
    pii_results = None
    if args.pii:
        console.print("[*] Running PII detection...", style="cyan")
        if args.bucket:
            findings = scan_bucket_for_pii(args.bucket)
            pii_results = {args.bucket: findings}
        else:
            pii_results = scan_all_buckets_for_pii(profile=args.profile)

    # ── Generate reports ──
    generate_html_report(results, pii_results=pii_results, output_dir=args.output)
    generate_json_report(results, pii_results=pii_results, output_dir=args.output)

    # ── Summary ──
    console.print(f"\n[green]✅ Scanned {len(results)} buckets[/green]")

    severity_styles = {'CRITICAL': 'red', 'HIGH': 'orange3', 'MEDIUM': 'yellow', 'LOW': 'green'}
    for r in results:
        style = severity_styles.get(r.risk_level, 'white')
        console.print(
            f"  [[{style}]{r.risk_level}[/{style}]] {r.name} — {len(r.findings)} finding(s)"
        )

if __name__ == '__main__':
    main()