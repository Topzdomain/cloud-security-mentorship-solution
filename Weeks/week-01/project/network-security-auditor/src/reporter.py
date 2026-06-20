import json
from datetime import datetime
from pathlib import Path
from typing import List
from .sg_checker import SGFinding
from .vpc_checker import VPCFinding
from .nacl_checker import NACLFinding
from .iam_checker import IAMFinding

SEVERITY_ORDER = {'CRITICAL': 0, 'HIGH': 1, 'MEDIUM': 2, 'LOW': 3, 'INFO': 4}

def generate_report(sg_findings: List[SGFinding], vpc_findings: List[VPCFinding],
                    nacl_findings: List[NACLFinding], iam_findings: List[IAMFinding], region: str,
                    output_dir: str = 'reports') -> dict:
    Path(output_dir).mkdir(exist_ok=True)
    timestamp = datetime.utcnow().strftime('%Y-%m-%d_%H-%M-%S')

    all_findings = sg_findings + vpc_findings + nacl_findings + iam_findings

    report = {
        'report_metadata': {
            'timestamp': datetime.utcnow().isoformat(),
            'region': region,
            'tool': 'Network Security Auditor v2.0',
        },
        'summary': {
            'total_findings': len(all_findings),
            'critical': sum(1 for f in all_findings if f.severity == 'CRITICAL'),
            'high': sum(1 for f in all_findings if f.severity == 'HIGH'),
            'medium': sum(1 for f in all_findings if f.severity == 'MEDIUM'),
            'low': sum(1 for f in all_findings if f.severity == 'LOW'),
            'info': sum(1 for f in all_findings if f.severity == 'INFO'),
        },
        'security_group_findings': [vars(f) for f in sorted(sg_findings, key=lambda x: SEVERITY_ORDER.get(x.severity, 9))],
        'vpc_findings': [vars(f) for f in sorted(vpc_findings, key=lambda x: SEVERITY_ORDER.get(x.severity, 9))],
        'network_acl_findings': [vars(f) for f in sorted(nacl_findings, key=lambda x: SEVERITY_ORDER.get(x.severity, 9))],
        'iam_findings': [vars(f) for f in sorted(iam_findings, key=lambda x: SEVERITY_ORDER.get(x.severity,9))]
    }

    json_path = f"{output_dir}/{timestamp}-network-audit.json"
    with open(json_path, 'w') as f:
        json.dump(report, f, indent=2)

    print(f"[+] JSON report saved: {json_path}")
    return report