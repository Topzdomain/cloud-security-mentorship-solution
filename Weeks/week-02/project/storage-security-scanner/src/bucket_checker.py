import boto3
import json
from botocore.exceptions import ClientError
from dataclasses import dataclass, field
from typing import List, Dict
from datetime import datetime
from pathlib import Path
from rich.console import Console
from rich.table import Table
from rich import box
import argparse

console = Console()


# ─────────────────────────────────────────
#  Data Structure
# ─────────────────────────────────────────
@dataclass
class BucketResult:
    name: str
    region: str
    findings: List[Dict] = field(default_factory=list)

    @property
    def risk_score(self) -> int:
        scores = {'CRITICAL': 40, 'HIGH': 20, 'MEDIUM': 10, 'LOW': 5}
        return sum(scores.get(f['severity'], 0) for f in self.findings)

    @property
    def risk_level(self) -> str:
        score = self.risk_score
        if score >= 40: return 'CRITICAL'
        if score >= 20: return 'HIGH'
        if score >= 10: return 'MEDIUM'
        return 'LOW'


# ─────────────────────────────────────────
#  Scanning Orchestration
# ─────────────────────────────────────────
def scan_all_buckets(profile: str = None) -> List[BucketResult]:
    session = boto3.Session(profile_name=profile) if profile else boto3.Session()
    s3 = session.client('s3')

    buckets = s3.list_buckets().get('Buckets', [])
    results = []

    for bucket in buckets:
        name = bucket['Name']
        console.print(f"  [cyan]Scanning:[/cyan] {name}")
        result = scan_bucket(s3, name)
        results.append(result)

    return sorted(results, key=lambda x: x.risk_score, reverse=True)


def scan_bucket(s3_client, bucket_name: str) -> BucketResult:
    try:
        region_info = s3_client.get_bucket_location(Bucket=bucket_name)
        region = region_info.get('LocationConstraint') or 'us-east-1'
    except ClientError:
        region = 'unknown'

    result = BucketResult(name=bucket_name, region=region)

    _check_public_access_block(s3_client, bucket_name, result)
    _check_acl(s3_client, bucket_name, result)
    _check_bucket_policy(s3_client, bucket_name, result)
    _check_encryption(s3_client, bucket_name, result)
    _check_versioning(s3_client, bucket_name, result)
    _check_logging(s3_client, bucket_name, result)
    _check_mfa_delete(s3_client, bucket_name, result)

    return result


# ─────────────────────────────────────────
#  Check Functions
# ─────────────────────────────────────────
def _check_public_access_block(s3, name, result):
    try:
        pab = s3.get_public_access_block(Bucket=name)['PublicAccessBlockConfiguration']
        missing = [k for k, v in pab.items() if not v]
        if missing:
            result.findings.append({
                'severity': 'HIGH',
                'check': 'PUBLIC_ACCESS_BLOCK',
                'detail': f"Block Public Access settings not fully enabled: {', '.join(missing)}"
            })
    except ClientError as e:
        if 'NoSuchPublicAccessBlockConfiguration' in str(e):
            result.findings.append({
                'severity': 'CRITICAL',
                'check': 'PUBLIC_ACCESS_BLOCK',
                'detail': 'No Block Public Access configuration found — bucket may be publicly accessible'
            })


def _check_acl(s3, name, result):
    try:
        acl = s3.get_bucket_acl(Bucket=name)
        for grant in acl.get('Grants', []):
            grantee = grant.get('Grantee', {})
            if grantee.get('URI') in (
                'http://acs.amazonaws.com/groups/global/AllUsers',
                'http://acs.amazonaws.com/groups/global/AuthenticatedUsers'
            ):
                perm = grant.get('Permission', 'UNKNOWN')
                result.findings.append({
                    'severity': 'CRITICAL',
                    'check': 'PUBLIC_ACL',
                    'detail': f"Bucket ACL grants {perm} to {grantee['URI'].split('/')[-1]}"
                })
    except ClientError:
        pass


def _check_bucket_policy(s3, name, result):
    try:
        policy = json.loads(s3.get_bucket_policy(Bucket=name)['Policy'])
        for stmt in policy.get('Statement', []):
            if stmt.get('Effect') == 'Allow' and stmt.get('Principal') in ('*', {'AWS': '*'}):
                result.findings.append({
                    'severity': 'CRITICAL',
                    'check': 'PUBLIC_BUCKET_POLICY',
                    'detail': f"Bucket policy allows public access: Action={stmt.get('Action')}"
                })
    except ClientError as e:
        if 'NoSuchBucketPolicy' not in str(e):
            pass


def _check_encryption(s3, name, result):
    try:
        s3.get_bucket_encryption(Bucket=name)
    except ClientError:
        result.findings.append({
            'severity': 'HIGH',
            'check': 'NO_ENCRYPTION',
            'detail': 'No default server-side encryption configured on bucket'
        })


def _check_versioning(s3, name, result):
    versioning = s3.get_bucket_versioning(Bucket=name)
    if versioning.get('Status') != 'Enabled':
        result.findings.append({
            'severity': 'MEDIUM',
            'check': 'VERSIONING_DISABLED',
            'detail': 'Object versioning is not enabled — accidental deletions cannot be recovered'
        })


def _check_logging(s3, name, result):
    logging_cfg = s3.get_bucket_logging(Bucket=name)
    if 'LoggingEnabled' not in logging_cfg:
        result.findings.append({
            'severity': 'MEDIUM',
            'check': 'NO_ACCESS_LOGGING',
            'detail': 'Server access logging is disabled — no audit trail for object access'
        })


def _check_mfa_delete(s3, name, result):
    versioning = s3.get_bucket_versioning(Bucket=name)
    if versioning.get('MFADelete') != 'Enabled':
        result.findings.append({
            'severity': 'LOW',
            'check': 'NO_MFA_DELETE',
            'detail': 'MFA Delete not enabled — objects can be permanently deleted without MFA'
        })


# ─────────────────────────────────────────
#  Output — Console Table
# ─────────────────────────────────────────
def print_results_table(results: List[BucketResult]):
    table = Table(title="S3 Security Audit Findings", box=box.ROUNDED, show_lines=True)
    table.add_column("Bucket", width=35)
    table.add_column("Region", width=15)
    table.add_column("Risk Level", width=10)
    table.add_column("Findings", width=10)
    table.add_column("Top Issue", width=40)

    severity_styles = {
        'CRITICAL': 'red',
        'HIGH':     'orange3',
        'MEDIUM':   'yellow',
        'LOW':      'green'
    }

    for r in results:
        style = severity_styles.get(r.risk_level, 'white')
        top_issue = r.findings[0]['detail'] if r.findings else 'None'
        table.add_row(
            r.name,
            r.region,
            f"[{style}]{r.risk_level}[/{style}]",
            str(len(r.findings)),
            top_issue
        )

    console.print(table)


# ─────────────────────────────────────────
#  Output — JSON Report
# ─────────────────────────────────────────
def generate_report(results: List[BucketResult], output_dir: str = 'reports') -> dict:
    Path(output_dir).mkdir(exist_ok=True)
    timestamp = datetime.utcnow().strftime('%Y-%m-%d_%H-%M-%S')

    all_findings = [f for r in results for f in r.findings]

    report = {
        'report_metadata': {
            'timestamp': datetime.utcnow().isoformat(),
            'tool': 'S3 Security Auditor',
            'total_buckets_scanned': len(results),
        },
        'summary': {
            'total_findings': len(all_findings),
            'critical': sum(1 for f in all_findings if f['severity'] == 'CRITICAL'),
            'high':     sum(1 for f in all_findings if f['severity'] == 'HIGH'),
            'medium':   sum(1 for f in all_findings if f['severity'] == 'MEDIUM'),
            'low':      sum(1 for f in all_findings if f['severity'] == 'LOW'),
        },
        'bucket_results': [
            {
                'name':       r.name,
                'region':     r.region,
                'risk_level': r.risk_level,
                'risk_score': r.risk_score,
                'findings':   r.findings,
            }
            for r in results
        ]
    }

    json_path = f"{output_dir}/{timestamp}-s3-audit.json"
    with open(json_path, 'w') as f:
        json.dump(report, f, indent=2)

    console.print(f"\n[+] JSON report saved: [green]{json_path}[/green]")
    return report


# ─────────────────────────────────────────
#  Entry Point
# ─────────────────────────────────────────
def main():
    parser = argparse.ArgumentParser(description='S3 Security Auditor')
    parser.add_argument('--profile', default=None, help='AWS profile to use')
    parser.add_argument('--output', default='reports', help='Output directory for reports')
    args = parser.parse_args()

    console.print("\n[bold blue]🪣 S3 Security Auditor[/bold blue]\n")
    console.print("[*] Scanning all S3 buckets...\n", style="cyan")

    results = scan_all_buckets(profile=args.profile)

    print_results_table(results)

    report = generate_report(results, args.output)

    console.print(f"\n[bold green]✅ Scan Complete![/bold green]")
    console.print(f"   Buckets scanned: [white]{report['report_metadata']['total_buckets_scanned']}[/white]")
    console.print(f"   Critical:        [red]{report['summary']['critical']}[/red]")
    console.print(f"   High:            [orange3]{report['summary']['high']}[/orange3]")
    console.print(f"   Medium:          [yellow]{report['summary']['medium']}[/yellow]")
    console.print(f"   Low:             [green]{report['summary']['low']}[/green]")


if __name__ == '__main__':
    main()