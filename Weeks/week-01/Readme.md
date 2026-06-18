# AWS Network Security Auditor

A Python-based security tool that scans AWS VPC and Security Group configurations for common misconfigurations, producing severity-graded JSON and HTML reports. Supporting infrastructure (intentionally including misconfigurations to validate detection) is provisioned via Terraform.

---

## Overview

This project simulates a real-world cloud security workflow in two phases:

1. **Provision** — Terraform deploys a VPC, subnets, security groups, and VPC Flow Logs (delivered to both CloudWatch Logs and S3).
2. **Audit** — A Python tool connects to the live AWS environment via `boto3`, evaluates the deployed resources against security best practices, and generates a severity-graded report of findings.

The goal: build the kind of tool a cloud security engineer would actually use to continuously audit an AWS environment for drift and misconfiguration.

---

## Architecture

```
Terraform                          Python Auditor
─────────                          ──────────────
VPC + Subnets        ──────►       vpc_checker.py
Security Groups      ──────►       sg_checker.py
Flow Logs (S3 + CW)                      │
                                          ▼
                                    auditor.py (orchestrator)
                                          │
                                          ▼
                                    reporter.py
                                          │
                            ┌─────────────┴─────────────┐
                            ▼                            ▼
                    audit_report.json            audit_report.html
```

*(Replace this with an actual diagram image if you create one — even a simple draw.io export adds a lot of credibility.)*

---

## Tech Stack

| Layer | Tools |
|---|---|
| Infrastructure | Terraform, AWS (VPC, Subnets, Security Groups, Flow Logs, S3, CloudWatch, IAM) |
| Detection logic | Python, boto3 |
| Testing | pytest, moto (mocked AWS for unit tests, no live account needed) |
| Reporting | Jinja2 (HTML), JSON |
| CLI output | rich |

---

## Repository Structure

```
network-security-auditor/
├── terraform/
│   ├── vpc.tf                 # VPC, subnets, route tables
│   ├── security_groups.tf     # SG definitions (some intentionally misconfigured)
│   ├── vpc_flow_logs.tf        # Flow logs → S3 + CloudWatch
│   └── outputs.tf
├── src/
│   ├── __init__.py
│   ├── auditor.py             # Orchestrates the scan
│   ├── sg_checker.py          # Security Group misconfiguration checks
│   ├── vpc_checker.py         # VPC-level checks (flow logs, default VPC, CIDR)
│   └── reporter.py            # JSON + HTML report generation
├── tests/
│   ├── test_sg_checker.py
│   └── test_vpc_checker.py
├── requirements.txt
└── README.md
```

---

## Infrastructure (Terraform)

The Terraform configuration provisions a realistic but intentionally imperfect environment to validate the auditor against real findings rather than a theoretical clean environment:

- A custom VPC with public and private subnets
- Security Groups, including one deliberately misconfigured (e.g. SSH open to `0.0.0.0/0`) to confirm detection works
- VPC Flow Logs delivered to **both** an S3 bucket (cheap, long-term storage) and a CloudWatch Log Group (real-time querying via CloudWatch Insights)
- IAM role scoped specifically for Flow Log delivery to CloudWatch (S3 delivery uses bucket policy, not IAM role)

```bash
cd terraform
terraform init
terraform plan
terraform apply
```

---

## Detection Logic (Python)

| Module | Responsibility |
|---|---|
| `vpc_checker.py` | Flags missing Flow Logs, default VPC usage, overly broad CIDR blocks |
| `sg_checker.py` | Flags Security Groups with open dangerous ports (SSH, RDP, databases) exposed to `0.0.0.0/0` or `::/0` |
| `auditor.py` | Orchestrates checks across all resources in the target region |
| `reporter.py` | Converts findings into severity-graded JSON and a styled HTML report |

### Running the auditor
```bash
source venv/Scripts/activate      # Windows Git Bash
pip install -r requirements.txt
python src/auditor.py
```

Outputs:
- `audit_report.json` — machine-readable findings
- `audit_report.html` — human-readable report with severity breakdown

---

## Testing

Unit tests use `moto` to mock AWS services entirely — no live AWS account or cost required to run them.

```bash
pytest tests/ -v
```

*(Insert screenshot of passing tests here)*

---

## Sample Findings

| Severity | Example Finding |
|---|---|
| CRITICAL | Security Group allows inbound traffic on port 22 (SSH) from `0.0.0.0/0` |
| MEDIUM | VPC Flow Logs are disabled on `vpc-xxxxxxxx` |
| LOW | VPC uses an overly broad `/16` CIDR block |

*(Insert HTML report screenshot here)*

---

## Lessons Learned

- `iam_role_arn` is only applicable for CloudWatch Flow Log delivery — S3 delivery relies on bucket policy, not an IAM role. Passing it to both caused a `terraform apply` failure that clarified this distinction.
- Auditing against a deliberately broken environment (rather than a clean one) was necessary to actually validate the detection logic — a clean environment would have returned zero findings either way, broken script or not.
- `moto` v5+ consolidated per-service mock decorators (`mock_ec2`, `mock_s3`, etc.) into a single `mock_aws` decorator — a good reminder that fast-moving Python libraries can make tutorial code stale quickly.

---

## Future Improvements

- Add IAM policy auditing (overly permissive roles, wildcard actions)
- Add S3 bucket public-access auditing
- Schedule recurring scans via Lambda + EventBridge
- Send CRITICAL findings to SNS/Slack for real-time alerting