import json
from datetime import datetime
from pathlib import Path
from typing import List, Dict
from jinja2 import Template

HTML_TEMPLATE = """
<!DOCTYPE html>
<html lang="en">
<head>
    <title>S3 Security Report</title>
    <style>
        * { margin: 0; padding: 0; box-sizing: border-box; }
        body { font-family: Arial, sans-serif; background: #f5f5f5; padding: 20px; color: #333; }
        .header { background: #1a1a2e; color: white; padding: 20px 25px; border-radius: 8px; margin-bottom: 20px; }
        .header h1 { font-size: 1.6rem; margin-bottom: 5px; }
        .header p  { color: #adb5bd; font-size: 0.9rem; }

        .summary { display: flex; gap: 15px; margin-bottom: 25px; }
        .stat-card { background: white; padding: 15px; border-radius: 8px; text-align: center; flex: 1; box-shadow: 0 1px 3px rgba(0,0,0,0.1); }
        .stat-card h2 { font-size: 2rem; margin-bottom: 4px; }
        .stat-card p  { font-size: 0.85rem; color: #6c757d; text-transform: uppercase; letter-spacing: .05em; }
        .card-critical { border-top: 4px solid #dc3545; }
        .card-high     { border-top: 4px solid #fd7e14; }
        .card-medium   { border-top: 4px solid #ffc107; }
        .card-low      { border-top: 4px solid #28a745; }

        h2.section-title {
            font-size: 1.1rem; text-transform: uppercase; letter-spacing: .06em;
            color: #6c757d; margin: 30px 0 12px; padding-bottom: 8px;
            border-bottom: 2px solid #dee2e6;
        }

        table { width: 100%; border-collapse: collapse; background: white;
                border-radius: 8px; overflow: hidden; box-shadow: 0 1px 3px rgba(0,0,0,0.1);
                margin-bottom: 30px; }
        th { background: #343a40; color: white; padding: 12px 14px; text-align: left; font-size: 0.88rem; }
        td { padding: 10px 14px; border-bottom: 1px solid #dee2e6; font-size: 0.9rem; }
        tr:last-child td { border-bottom: none; }
        tr.subrow { background: #f8f9fa; }
        tr.subrow td { color: #555; }

        .badge {
            display: inline-block; padding: 2px 10px; border-radius: 4px;
            font-size: 0.78rem; font-weight: 700; letter-spacing: .04em;
        }
        .badge-critical { background: #dc3545; color: white; }
        .badge-high     { background: #fd7e14; color: white; }
        .badge-medium   { background: #ffc107; color: #333; }
        .badge-low      { background: #28a745; color: white; }
        .badge-info     { background: #0d6efd; color: white; }

        .no-findings { background: white; border-radius: 8px; padding: 30px;
                       text-align: center; color: #6c757d; box-shadow: 0 1px 3px rgba(0,0,0,0.1); }
        .indent { padding-left: 30px; color: #888; }
    </style>
</head>
<body>

    <!-- Header -->
    <div class="header">
        <h1>🔒 S3 Security &amp; PII Report</h1>
        <p>Generated: {{ timestamp }} &nbsp;|&nbsp; Buckets Scanned: {{ total_buckets }}</p>
    </div>

    <!-- Summary Cards -->
    <div class="summary">
        <div class="stat-card card-critical">
            <h2 style="color:#dc3545">{{ critical }}</h2><p>Critical</p>
        </div>
        <div class="stat-card card-high">
            <h2 style="color:#fd7e14">{{ high }}</h2><p>High</p>
        </div>
        <div class="stat-card card-medium">
            <h2 style="color:#ffc107">{{ medium }}</h2><p>Medium</p>
        </div>
        <div class="stat-card card-low">
            <h2 style="color:#28a745">{{ low }}</h2><p>Low</p>
        </div>
    </div>

    <!-- Section 1: S3 Bucket Misconfigurations -->
    <h2 class="section-title">🪣 S3 Bucket Misconfiguration Findings</h2>

    {% if buckets %}
    <table>
        <tr>
            <th>Bucket</th>
            <th>Region</th>
            <th>Risk Level</th>
            <th>Issues</th>
        </tr>
        {% for bucket in buckets %}
        <tr>
            <td><strong>{{ bucket.name }}</strong></td>
            <td>{{ bucket.region }}</td>
            <td>
                <span class="badge badge-{{ bucket.risk_level.lower() }}">
                    {{ bucket.risk_level }}
                </span>
            </td>
            <td>{{ bucket.findings | length }} issue(s)</td>
        </tr>
        {% for finding in bucket.findings %}
        <tr class="subrow">
            <td class="indent" colspan="2">↳ {{ finding.check }}</td>
            <td>
                <span class="badge badge-{{ finding.severity.lower() }}">
                    {{ finding.severity }}
                </span>
            </td>
            <td>{{ finding.detail }}</td>
        </tr>
        {% endfor %}
        {% endfor %}
    </table>
    {% else %}
    <div class="no-findings">✅ No S3 misconfiguration findings detected.</div>
    {% endif %}

    <!-- Section 2: PII Detection -->
    <h2 class="section-title">🔍 PII Detection Findings</h2>

    {% if pii_findings %}
    <table>
        <tr>
            <th>Severity</th>
            <th>Bucket</th>
            <th>Object Key</th>
            <th>PII Type</th>
            <th>Matches</th>
            <th>Masked Sample</th>
        </tr>
        {% for f in pii_findings %}
        <tr>
            <td>
                <span class="badge badge-{{ f.severity.lower() }}">
                    {{ f.severity }}
                </span>
            </td>
            <td>{{ f.bucket }}</td>
            <td>{{ f.object_key }}</td>
            <td>{{ f.pii_type }}</td>
            <td>{{ f.match_count }}</td>
            <td><code>{{ f.sample }}</code></td>
        </tr>
        {% endfor %}
    </table>
    {% else %}
    <div class="no-findings">✅ No PII detected across scanned objects.</div>
    {% endif %}

</body>
</html>
"""


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

    # S3 misconfiguration findings (from BucketResult.findings — list of dicts)
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

    html = Template(HTML_TEMPLATE).render(
        timestamp=datetime.utcnow().strftime('%Y-%m-%d %H:%M UTC'),
        total_buckets=len(results),
        critical=sum(1 for f in all_findings if f.get('severity') == 'CRITICAL'),
        high    =sum(1 for f in all_findings if f.get('severity') == 'HIGH'),
        medium  =sum(1 for f in all_findings if f.get('severity') == 'MEDIUM'),
        low     =sum(1 for f in all_findings if f.get('severity') == 'LOW'),
        buckets=results,
        pii_findings=pii_findings,
    )

    path = f"{output_dir}/{timestamp}-s3-security.html"
    with open(path, 'w') as f:
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