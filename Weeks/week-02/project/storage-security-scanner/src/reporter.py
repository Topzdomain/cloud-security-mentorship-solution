import json
from datetime import datetime
from pathlib import Path
from typing import List, Dict
from jinja2 import Environment, FileSystemLoader


# ─────────────────────────────────────────
#  Jinja2 Environment
# ─────────────────────────────────────────
def _get_template():
    """
    Load the HTML template from the templates/ directory.
    FileSystemLoader resolves the path relative to the project root —
    run your scanner from the project root directory, not from inside src/.
    """
    env = Environment(loader=FileSystemLoader('templates'))
    return env.get_template('report.html.j2')


# ─────────────────────────────────────────
#  HTML Report Generator
# ─────────────────────────────────────────
def generate_html_report(results, pii_results: Dict[str, List[Dict]] = None,
                          output_dir: str = 'reports') -> str:
    """
    Generate a combined HTML report covering S3 misconfigurations and PII findings.

    Args:
        results:     List of BucketResult objects from s3_auditor.py
        pii_results: Dict of {bucket_name: [findings]} from pii_detector.py
        output_dir:  Directory to write the report into
    """
    Path(output_dir).mkdir(exist_ok=True)
    timestamp = datetime.utcnow().strftime('%Y-%m-%d_%H-%M-%S')

    # S3 misconfiguration findings
    all_s3_findings = [f for r in results for f in r.findings]

    # Flatten and sort PII findings by severity
    severity_order = {'CRITICAL': 0, 'HIGH': 1, 'MEDIUM': 2, 'LOW': 3}
    pii_findings = []
    if pii_results:
        pii_findings = sorted(
            [f for findings in pii_results.values() for f in findings],
            key=lambda x: severity_order.get(x['severity'], 9)
        )

    # Combined severity counts for summary cards
    all_findings = all_s3_findings + pii_findings

    template = _get_template()
    html = template.render(
        timestamp    =datetime.utcnow().strftime('%Y-%m-%d %H:%M UTC'),
        total_buckets=len(results),
        critical     =sum(1 for f in all_findings if f.get('severity') == 'CRITICAL'),
        high         =sum(1 for f in all_findings if f.get('severity') == 'HIGH'),
        medium       =sum(1 for f in all_findings if f.get('severity') == 'MEDIUM'),
        low          =sum(1 for f in all_findings if f.get('severity') == 'LOW'),
        buckets      =results,
        pii_findings =pii_findings,
    )

    path = f"{output_dir}/{timestamp}-s3-security.html"
    with open(path, 'w', encoding='utf-8') as f:
        f.write(html)

    print(f"[+] HTML report saved: {path}")
    return path


# ─────────────────────────────────────────
#  JSON Report Generator
# ─────────────────────────────────────────
def generate_json_report(results, pii_results: Dict[str, List[Dict]] = None,
                          output_dir: str = 'reports') -> dict:
    """
    Generate a combined JSON report covering S3 misconfigurations and PII findings.

    Args:
        results:     List of BucketResult objects from s3_auditor.py
        pii_results: Dict of {bucket_name: [findings]} from pii_detector.py
        output_dir:  Directory to write the report into
    """
    Path(output_dir).mkdir(exist_ok=True)
    timestamp = datetime.utcnow().strftime('%Y-%m-%d_%H-%M-%S')

    all_s3_findings = [f for r in results for f in r.findings]
    pii_findings    = [f for findings in (pii_results or {}).values() for f in findings]
    all_findings    = all_s3_findings + pii_findings

    report = {
        'report_metadata': {
            'timestamp':             datetime.utcnow().isoformat(),
            'tool':                  'S3 Security & PII Scanner',
            'total_buckets_scanned': len(results),
        },
        'summary': {
            'total_findings': len(all_findings),
            'critical':       sum(1 for f in all_findings if f.get('severity') == 'CRITICAL'),
            'high':           sum(1 for f in all_findings if f.get('severity') == 'HIGH'),
            'medium':         sum(1 for f in all_findings if f.get('severity') == 'MEDIUM'),
            'low':            sum(1 for f in all_findings if f.get('severity') == 'LOW'),
        },
        's3_misconfiguration_findings': [
            {
                'name':       r.name,
                'region':     r.region,
                'risk_level': r.risk_level,
                'risk_score': r.risk_score,
                'findings':   r.findings,
            }
            for r in results
        ],
        'pii_findings': pii_findings,
    }

    json_path = f"{output_dir}/{timestamp}-s3-security.json"
    with open(json_path, 'w') as f:
        json.dump(report, f, indent=2)

    print(f"[+] JSON report saved: {json_path}")
    return report