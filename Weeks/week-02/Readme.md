# Week 02 — Task: S3 Security Hardening & Sensitive Data Discovery with Amazon Macie

This directory documents the Week 2 task, which involved configuring S3 buckets with varying security postures, uploading sensitive data, and using Amazon Macie to discover and classify that data — simulating how a real cloud security engineer would audit an AWS environment for data exposure and compliance risk.

---

## Objective

- Provision S3 buckets with intentionally varied security configurations (some correctly hardened, some deliberately misconfigured) to create a realistic audit target
- Upload files containing Personally Identifiable Information (PII) to test Macie's sensitive data discovery capabilities
- Enable and configure Amazon Macie to scan for data exposure risks and classify sensitive data across the S3 environment

---

## S3 Buckets Provisioned

### `encryption-macie-bucket-1` (Primary Test Bucket)

| Setting | Configuration | Notes |
|---|---|---|
| Block Public Access | **Disabled** | Intentional — tests whether Macie and auditing tools flag the exposure risk |
| Bucket Policy | **None** | No policy explicitly granting public access — the bucket is not actually publicly readable despite public access being unblocked |
| Versioning | **Enabled** | Protects against accidental deletion and ransomware-style overwrites |
| Encryption | **SSE-KMS** | Server-side encryption using AWS KMS — stronger than SSE-S3 as key access can be independently audited and restricted |
| Contents | PII test file containing US phone numbers, SSNs, names |

### Additional Buckets (Misconfiguration Test Cases)

| Bucket Configuration | Security Issue | Expected Finding |
|---|---|---|
| Bucket policy explicitly granting public read access | Public data exposure | CRITICAL |
| Block public access disabled + public bucket policy | Full public read access | CRITICAL |
| Versioning disabled | No protection against overwrites or deletions | MEDIUM |
| No explicit encryption configuration | Relies on default SSE-S3 only | LOW/INFO |

---

## Why `encryption-macie-bucket-1` is an Interesting Test Case

Disabling "Block All Public Access" without adding a public bucket policy creates a **subtle but important distinction** worth understanding:

- **Block Public Access disabled** — removes the guardrail that prevents public policies from taking effect, but does not itself grant anyone access
- **No public bucket policy** — means no identity outside your AWS account has been explicitly granted access

The bucket is therefore **not publicly accessible in practice**, but it is **one policy statement away from being fully public**. This is exactly the kind of latent risk that Macie and S3 auditing tools should flag — the guardrail is gone even if the door isn't open yet. This mirrors real-world scenarios where misconfiguration is incremental, not always immediately catastrophic.

---

## PII Test Data Uploaded

A test file was uploaded to `encryption-macie-bucket-1` containing synthetic PII, including:

- US phone numbers
- Social Security Numbers (SSNs)
- Full names (first names and last names)
- Emails
- CreditCard Numbers
- Phone Numbers
- Date of Birth

This data was used to validate Macie's ability to discover and classify sensitive data at rest — not just flag bucket-level misconfigurations, but actually identify what's inside the buckets and how sensitive it is.

---

## Amazon Macie Configuration

### Enabling Macie
- Macie was enabled at the account and region level via the AWS Console
- Once enabled, Macie automatically begins monitoring S3 bucket-level security posture (public access, encryption status, replication, etc.)

### Sensitive Data Discovery Jobs
- Discovery jobs were created and run targeting the S3 buckets provisioned above
- Jobs were configured to scan for both default Macie managed data identifiers and custom-added sensitive data types

### Custom Sensitive Data Types Added
- Additional sensitive data identifiers were added beyond Macie's defaults to improve detection coverage — specifically to ensure the PII types uploaded (SSNs, phone numbers) were targeted explicitly

### Macie Findings Generated
Macie produced two categories of findings:

**Policy Findings** (bucket-level misconfigurations):
- `Policy:IAMUser/S3BucketPublicAccessGranted` — buckets with policies explicitly granting public access
- `Policy:IAMUser/S3BlockPublicAccessDisabled` — buckets where block public access has been turned off

**Sensitive Data Findings** (data classification):
- `SensitiveData:S3Object/Personal` — SSNs, names, and phone numbers detected in uploaded test file

*(Insert screenshot of Macie findings dashboard here)*
*(Insert screenshot of sensitive data discovery job results here)*

---

## Key Concepts Demonstrated

**SSE-KMS vs SSE-S3**
Both encrypt data at rest, but SSE-KMS provides an independently auditable key — one can see exactly who used the key, when, and restrict access to it separately from S3 permissions. SSE-S3 uses keys managed entirely by AWS with no separate audit trail. For sensitive data, SSE-KMS is the appropriate choice.

**Block Public Access as a guardrail, not an access control**
Block Public Access is a preventive control that stops public bucket policies from taking effect — it doesn't grant or deny access itself. Disabling it doesn't make a bucket public; it removes the protection that would prevent a future policy from doing so. The risk is latent, not immediate — but Macie correctly flags it regardless.

**Macie's two-layer approach**
Macie operates at two levels simultaneously: bucket-level posture (is this bucket misconfigured?) and object-level classification (what sensitive data does it contain?). Most teams focus on the first layer — the second is where Macie's real value lies for compliance use cases (HIPAA, PCI-DSS, GDPR).

---

## Lessons Learned

- Disabling Block Public Access without adding a public bucket policy does not immediately expose data — but Macie correctly flags it as a policy finding because the protective guardrail has been removed, not because the data is currently accessible.
- Macie's default managed data identifiers cover a broad set of PII types, but adding custom sensitive data identifiers improves precision for specific data types present in your environment.
- Sensitive data discovery jobs are not free — each job scans objects and incurs cost based on data volume. For a learning environment, scoping jobs to specific buckets rather than scanning the entire account keeps costs predictable.
- SSE-KMS encryption initially blocked Macie from scanning encryption-macie-bucket-1, producing a "Permission denied — ensure that AWS KMS key policies allow Macie to retrieve and decrypt the bucket's objects" error. The root cause was that Macie's IAM service role did not have the necessary KMS permissions to decrypt the bucket's contents. The fix required two steps: (1) appending kms:Decrypt and kms:DescribeKey permissions to the KMS key policy, explicitly allowing Macie's service-linked IAM role; and (2) disabling and re-enabling Macie entirely for the updated policy to take effect — Macie does not pick up KMS policy changes dynamically without a restart. This reinforces an important distinction: SSE-KMS encryption and S3 access control are independent layers — granting S3 read access does not automatically grant the ability to decrypt KMS-protected objects. Both permissions must be explicitly in place.