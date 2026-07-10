# Week 01 — Task: AWS Infrastructure Deployment via Terraform

This directory contains the Terraform configurations written as part of the Week 1 task, which involved provisioning the AWS infrastructure that the Network Security Auditor project scans against.

---

## Objective

Provision a realistic AWS network environment from scratch using Terraform, including intentional misconfigurations, to serve as a live target for the security auditor built in the Week 1 project.

---

## Infrastructure Provisioned

| Resource | Description |
|---|---|
| **VPC** | Custom VPC (`network_auditor_vpc`) with a `/16` CIDR block |
| **Subnets** | Public and private subnets across availability zones |
| **Internet Gateway** | Attached to the VPC to enable public internet access |
| **Route Tables** | Public route table with a default route to the IGW |
| **Security Groups** | Multiple SGs, including deliberately misconfigured ones (open SSH, RDP, and database ports) to validate auditor detection |
| **Network ACL** | Default NACL modified to include a low-numbered permissive rule (port 23/Telnet at rule #50) to test NACL misconfiguration detection |
| **S3 Bucket** | Stores VPC Flow Logs long-term; versioning enabled, public access blocked, 90-day lifecycle expiry |
| **CloudWatch Log Group** | Receives VPC Flow Logs for real-time querying; 30-day retention |
| **VPC Flow Logs** | Two separate flow log resources — one delivering to S3, one to CloudWatch |
| **IAM Role** | Scoped role for CloudWatch Flow Log delivery (S3 delivery uses bucket policy, not IAM role) |

---

## Key Design Decisions

**Flow logs delivered to both S3 and CloudWatch simultaneously**
S3 is used for cheap long-term storage (no ingestion cost, queried via Athena). CloudWatch is used for real-time monitoring and alerting (higher cost, but supports live dashboards and CloudWatch Insights queries). This mirrors what most production environments actually do.

**Intentional misconfigurations were included by design**
A security auditor running against a clean environment would return zero findings regardless of whether the detection logic works. Deliberately broken resources (open SSH, exposed database ports, low-numbered NACL rules) are necessary to validate that the tool catches real issues, not just clean ones.

**NACL allow-all is left in place**
AWS's default NACL allows all traffic in both directions. This was retained intentionally — Security Groups are the actual access-control gate in AWS's layered model. The NACL's role here is to demonstrate defense-in-depth awareness, not to be the primary control.

---

## Intentional Misconfigurations (Auditor Test Cases)

| Resource | Misconfiguration | Expected Severity |
|---|---|---|
| Security Group `open_ssh_port` | Port 22 (SSH) open to `0.0.0.0/0` | CRITICAL |
| Security Group `open_ssh_port` | Port 3389 (RDP) open to `0.0.0.0/0` | CRITICAL |
| Security Group `open_sensitive_ports` | Port 5432 (PostgreSQL) open to `0.0.0.0/0` | HIGH |
| Default NACL | Rule #50 allows Telnet (port 23) from `0.0.0.0/0` | HIGH |
| Default NACL | Allow-all rule present (rule #100) | INFO |

---

## Usage

```bash
# Initialise Terraform and download providers
terraform init

# Preview what will be created
terraform plan

# Deploy infrastructure to AWS
terraform apply -auto-approve

# Tear down all resources when done (avoids ongoing charges)
terraform destroy -auto-approve
```