# AWS Network Security Auditor

A Python-based security tool that scans AWS network and identity configurations — VPCs, Security Groups, Network ACLs, and IAM roles — for common misconfigurations, producing a severity-graded JSON report. Supporting infrastructure (intentionally including misconfigurations to validate detection) is provisioned via Terraform.

---

## Overview

This project simulates a real-world cloud security workflow in two phases:

1. **Provision** — Terraform deploys a VPC, subnets, Security Groups, Network ACL rules, and VPC Flow Logs (delivered to both CloudWatch Logs and S3). Some resources are intentionally misconfigured to validate that the auditor actually detects real issues, rather than just returning a clean report regardless of whether the detection logic works.
2. **Audit** — A Python tool connects to the live AWS environment via `boto3`, evaluates the deployed resources against security best practices, and generates a severity-graded report of findings.

The goal: build the kind of tool a cloud security engineer would actually use to continuously audit an AWS environment for drift and misconfiguration — across both the network layer and the identity layer.

---

## Architecture

```
Terraform                          Python Auditor
─────────                          ──────────────
VPC + Subnets        ──────►       vpc_checker.py
Security Groups      ──────►       sg_checker.py
Network ACLs         ──────►       nacl_checker.py
IAM Roles            ──────►       iam_checker.py
Flow Logs (S3 + CW)                      │
                                          ▼
                                    auditor.py (orchestrator)
                                          │
                                          ▼
                                    reporter.py
                                          │
                                          ▼
                                  {timestamp}-network-audit.json
```

---

## Tech Stack

| Layer | Tools |
|---|---|
| Infrastructure | Terraform, AWS (VPC, Subnets, Security Groups, Network ACLs, Flow Logs, S3, CloudWatch, IAM) |
| Detection logic | Python, boto3 |
| Testing | pytest, moto (mocked AWS for unit tests, no live account needed) |
| Reporting | JSON (severity-graded) |
| CLI output | rich |

---

## Repository Structure

```
network-security-auditor/
├── terraform/
│   ├── vpc.tf                 # VPC, subnets, route tables
│   ├── security_groups.tf     # SG definitions (some intentionally misconfigured)
│   ├── nacl.tf                 # Default NACL rules (some intentionally permissive)
│   ├── vpc_flow_logs.tf        # Flow logs → S3 + CloudWatch
│   └── outputs.tf
├── src/
│   ├── __init__.py
│   ├── auditor.py             # Orchestrates all checks, prints results, triggers report
│   ├── sg_checker.py          # Security Group misconfiguration checks
│   ├── vpc_checker.py         # VPC-level checks (flow logs, default VPC, CIDR)
│   ├── nacl_checker.py        # Network ACL misconfiguration checks
│   ├── iam_checker.py         # IAM role / policy misconfiguration checks
│   └── reporter.py            # Aggregates findings into severity-graded JSON
├── tests/
│   └── test_sg_checker.py
├── requirements.txt
└── README.md
```

---

## Infrastructure (Terraform)

The Terraform configuration provisions a realistic but intentionally imperfect environment, so the auditor can be validated against real findings rather than a theoretical clean environment:

- A custom VPC with public and private subnets
- Security Groups, including one deliberately misconfigured (e.g. SSH open to `0.0.0.0/0`) to confirm detection works
- Default Network ACL rules, including an intentionally low-numbered permissive rule (Telnet open on port 23) to test rule-ordering detection
- VPC Flow Logs delivered to **both** an S3 bucket (cheap, long-term storage) and a CloudWatch Log Group (real-time querying via CloudWatch Insights)
- IAM role scoped specifically for Flow Log delivery to CloudWatch (S3 delivery uses a bucket policy, not an IAM role — passing `iam_role_arn` to both caused a real `terraform apply` failure during development, see Lessons Learned)

```bash
cd terraform
terraform init
terraform plan
terraform apply -auto-approve
```

---

## Detection Logic (Python)

| Module | Responsibility |
|---|---|
| `vpc_checker.py` | Flags missing Flow Logs, default VPC usage, overly broad CIDR blocks |
| `sg_checker.py` | Flags Security Groups with dangerous ports (SSH, RDP, databases) exposed to `0.0.0.0/0` or `::/0` |
| `nacl_checker.py` | Flags permissive NACL rules — dangerous ports, wide ingress port ranges, unusually low rule numbers, ICMP exposure, missing ephemeral-port egress coverage |
| `iam_checker.py` | Flags overly permissive IAM roles — wildcard actions/resources, `AdministratorAccess`, public trust policies, privilege-escalation primitives |
| `auditor.py` | Orchestrates all checks against the target region, prints a live results table, triggers report generation |
| `reporter.py` | Aggregates findings from all four checkers into a single severity-graded JSON report |


## Unit Testing (Mocked)

Unit tests use `moto` to mock AWS services entirely — no live AWS account or cost required to run them. These validate the detection logic in isolation.

```bash
pytest tests/ -v
```

![Unit Test Screenshot](https://raw.githubusercontent.com/Topzdomain/cloud-security-mentorship-solution/auditor-v2/Weeks/week-01/project/network-security-auditor/screenshots/mock-aws-test.png)


### Running the auditor
```bash
source venv/Scripts/activate      # Windows Git Bash
pip install -r requirements.txt
python -m src.auditor --region us-east-1
```

Output:
- `reports/{timestamp}-network-audit.json` — severity-graded findings across SG, VPC, NACL, and IAM

---

---

## Live AWS Integration Test

Beyond mocked unit tests, the project was validated end-to-end against a real AWS environment to confirm the auditor correctly detects misconfigurations in live infrastructure, not just simulated ones.

**Workflow:**

```bash
# 1. Deploy infrastructure (includes intentional misconfigurations)
cd terraform
terraform init
terraform apply -auto-approve

# 2. Run the auditor against the live environment
cd ..
source venv/Scripts/activate
python -m src.auditor --region us-east-1

# 3. Review the generated JSON report
reports/{timestamp}-network-audit.json

# 4. Tear down infrastructure to avoid ongoing AWS charges
cd terraform
terraform destroy -auto-approve
```

This confirmed the auditor correctly flagged: the deliberately misconfigured Security Group (open SSH to `0.0.0.0/0`), the low-numbered permissive NACL rule, and the absence of VPC Flow Logs prior to their creation — validating that detection logic works against real AWS API responses, not just `moto`'s simulated ones.

![Intentionally Misconfigured Network ACLs](https://raw.githubusercontent.com/Topzdomain/cloud-security-mentorship-solution/auditor-v2/Weeks/week-01/project/network-security-auditor/screenshots/intentionally-misconfigured-nacl.png)
![Result of Scan Flagging NACL Misconfiguration](https://raw.githubusercontent.com/Topzdomain/cloud-security-mentorship-solution/auditor-v2/Weeks/week-01/project/network-security-auditor/screenshots/v2-live-scan-page-3.png)

---

## JSON Findings EXCERPT

```bash
{
  "report_metadata": {
    "timestamp": "2026-06-19T09:37:21.145430",
    "region": "us-east-1",
    "tool": "Network Security Auditor v2.0"
  },
  "summary": {
    "total_findings": 22,
    "critical": 4,
    "high": 7,
    "medium": 1,
    "low": 3,
    "info": 7
  },
  "security_group_findings": [
    {
      "sg_id": "sg-0c68fc****",
      "sg_name": "open_ssh_port",
      "vpc_id": "vpc-01558****",
      "port": 22,
      "protocol": "tcp",
      "cidr": "0.0.0.0/0",
      "service": "SSH",
      "severity": "CRITICAL",
      "description": "Port 22 (SSH) open to the internet from 0.0.0.0/0"
    },
    {
      "sg_id": "sg-0c68fc****",
      "sg_name": "open_ssh_port",
      "vpc_id": "vpc-01558****",
      "port": 3389,
      "protocol": "tcp",
      "cidr": "0.0.0.0/0",
      "service": "RDP",
      "severity": "CRITICAL",
      "description": "Port 3389 (RDP) open to the internet from 0.0.0.0/0"
    },
    {
      "sg_id": "sg-0e18ca****",
      "sg_name": "open_sensitive_ports",
      "vpc_id": "vpc-01558****",
      "port": 5432,
      "protocol": "tcp",
      "cidr": "0.0.0.0/0",
      "service": "PostgreSQL",
      "severity": "HIGH",
      "description": "Port 5432 (PostgreSQL) open to the internet from 0.0.0.0/0"
    }
  ],
  "...": "22 total findings across Security Groups, VPCs, Network ACLs, and IAM roles"
}
```
---

## Lessons Learned

- `iam_role_arn` is only applicable for CloudWatch Flow Log delivery — S3 delivery relies on a bucket policy, not an IAM role. Passing it to both caused a `terraform apply` failure that clarified this distinction.
- Auditing against a deliberately broken environment (rather than a clean one) was necessary to actually validate the detection logic — a clean environment would have returned zero findings either way, broken script or not.
- `moto` v5+ consolidated per-service mock decorators (`mock_ec2`, `mock_s3`, etc.) into a single `mock_aws` decorator — a reminder that fast-moving Python libraries can make tutorial code stale quickly.
- Severity is contextual, not absolute. A NACL "allow-all" rule was initially scored CRITICAL, but Security Groups are the actual access-control gate in most real environments — the rule was downgraded to INFO to avoid alert fatigue and reserve CRITICAL for findings that genuinely grant access on their own.
- Ports 80/443 open to `0.0.0.0/0` are not inherently a misconfiguration for public-facing services — flagging them at the same severity as SSH/RDP exposure would create noise that drowns out genuinely dangerous findings.

---

## Known Limitations — IAM Auditor (`iam_checker.py`)

- **`NotAction` / `NotResource` are not evaluated.** These IAM policy elements invert the matching logic (e.g. "allow everything *except* these actions"). The current checker only parses `Action` and `Resource`, so a policy built around `NotAction` would be misread or skipped entirely.
- **`Condition` blocks are not factored into severity.** A wildcard action gated behind an MFA-required or IP-restricted condition is meaningfully less risky than the same wildcard with no condition — the checker currently treats both identically, which can overstate risk.
- **The privilege-escalation action list is not exhaustive.** It covers common, high-signal primitives (e.g. `iam:PassRole`, `iam:CreateAccessKey`), but documented AWS IAM privilege-escalation research identifies 20+ distinct paths. Coverage should be expanded over time.
- **No usage-based risk weighting.** A role that's never been assumed and a role assumed thousands of times per day are scored identically if their policy documents look the same — last-used data (available via IAM Access Analyzer / credential reports) isn't factored in yet.
- **AWS service-linked roles are skipped entirely**, by design — they're managed by AWS and can't be edited, so flagging them would be noise with no possible remediation.

---

## Future Improvements

- Address the IAM auditor limitations above — `Condition`-aware severity scoring, expanded privilege-escalation coverage, `NotAction`/`NotResource` support
- Add S3 bucket public-access auditing
- Make NACL/SG port-exposure severity contextual to subnet placement (public vs. private subnet), rather than absolute
- Restore HTML report generation alongside JSON for easier human review
- Schedule recurring scans via Lambda + EventBridge
- Send CRITICAL findings to SNS/Slack for real-time alerting