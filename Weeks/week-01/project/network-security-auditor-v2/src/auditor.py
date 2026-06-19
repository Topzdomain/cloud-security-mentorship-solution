#!/usr/bin/env python3
"""AWS Network Security Auditor — Main Entry Point"""

import argparse
import sys
from rich.console import Console
from rich.table import Table
from rich import box

from .sg_checker import check_security_groups
from .vpc_checker import check_vpcs
from .reporter import generate_report

console = Console()

def main():
    parser = argparse.ArgumentParser(description='AWS Network Security Auditor')
    parser.add_argument('--region', default='us-east-1', help='AWS region to scan')
    parser.add_argument('--output', default='reports', help='Output directory for reports')
    args = parser.parse_args()

    console.print(f"\n[bold blue]🔍 AWS Network Security Auditor[/bold blue]")
    console.print(f"Region: [yellow]{args.region}[/yellow]\n")

    # Run checks
    console.print("[*] Scanning Security Groups...", style="cyan")
    sg_findings = check_security_groups(args.region)
    
    console.print("[*] Scanning VPCs...", style="cyan")
    vpc_findings = check_vpcs(args.region)
    
    # Print results table
    table = Table(title="Security Findings", box=box.ROUNDED, show_lines=True)
    table.add_column("Severity", style="bold", width=10)
    table.add_column("Resource", width=25)
    table.add_column("Issue", width=40)
    
    severity_styles = {'CRITICAL': 'red', 'HIGH': 'orange3', 'MEDIUM': 'yellow', 'LOW': 'green'}
    
    for f in sg_findings:
        style = severity_styles.get(f.severity, 'white')
        table.add_row(f"[{style}]{f.severity}[/{style}]", f.sg_id, f.description)
    
    for f in vpc_findings:
        style = severity_styles.get(f.severity, 'white')
        table.add_row(f"[{style}]{f.severity}[/{style}]", f.vpc_id, f.description)
    
    console.print(table)
    
    # Generate report
    report = generate_report(sg_findings, vpc_findings, args.region, args.output)
    
    console.print(f"\n[bold green]✅ Scan Complete![/bold green]")
    console.print(f"   Critical: [red]{report['summary']['critical']}[/red]")
    console.print(f"   High:     [orange3]{report['summary']['high']}[/orange3]")
    console.print(f"   Medium:   [yellow]{report['summary']['medium']}[/yellow]")

if __name__ == '__main__':
    main()