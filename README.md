# AWS IAM Security Auditor

A Python CLI tool that audits AWS IAM configuration against CIS AWS Foundations Benchmark controls and least-privilege best practices. I built this because IAM misconfiguration overly permissive roles, stale credentials, missing MFA is one of the most common root causes of AWS account compromise, and it's largely preventable with basic automated checks.

---

## Security Checks

| Check | What It Detects | Severity |
|---|---|---|
| MFA Not Enabled | IAM users with no MFA device attached | HIGH |
| Inactive Users | Users with no console login in 90+ days | MEDIUM |
| Access Keys Not Rotated | Active access keys older than 90 days | HIGH |
| AdministratorAccess Policy | Users or roles with full admin access | HIGH |
| Root Account Activity | Recent root login or active root access keys | HIGH |
| Dual Access | Users with both console and programmatic access | MEDIUM |
| Password Policy | Account policy vs CIS benchmark minimums | MEDIUM |

---

## Setup

### Prerequisites

- Python 3.8+
- AWS account (free tier works)
- IAM user with `SecurityAudit` policy attached — see note below

### IAM Permissions

I use a dedicated IAM user (`iam-auditor-bot`) with only the AWS managed `SecurityAudit` policy. It's read-only — it can list and describe IAM resources but can't change anything. This is intentional. If these credentials were ever leaked, the blast radius is limited to someone reading your IAM config, not altering it.

Do not use root credentials or an admin user to run this.

### Install

```bash
git clone https://github.com/Mimic360/aws-iam-security-auditor.git
cd aws-iam-security-auditor

python -m venv venv
venv\Scripts\activate        # Windows
# source venv/bin/activate   # macOS/Linux

pip install -r requirements.txt
```

### Configure

Copy `.env.example` to `.env` and fill in your credentials:

```bash
cp .env.example .env
```

```env
AWS_ACCESS_KEY_ID=your_key_here
AWS_SECRET_ACCESS_KEY=your_secret_here
AWS_DEFAULT_REGION=ap-southeast-2
```

`.env` is gitignored and should never be committed. If you accidentally push credentials to a public repo, rotate them immediately — bots scrape GitHub for AWS keys and can rack up thousands in charges within minutes.

### Run

```bash
python main.py
```

---

## Sample Output

```
Starting AWS IAM Security Audit...
This may take a moment depending on account size.

  Checking: check_mfa_enabled...
  Checking: check_inactive_users...
  Checking: check_old_access_keys...
  Checking: check_admin_policy_attached...
  Checking: check_root_account_activity...
  Checking: check_dual_access_users...
  Checking: check_password_policy...

============================================================
  AWS IAM SECURITY AUDIT REPORT
============================================================
  Total checks : 7
  PASS          : 3
  FAIL          : 3
  WARN          : 1
============================================================

FINDINGS

  [FAIL]  HIGH  MFA Not Enabled
         2 user(s) have no MFA device. A stolen password alone grants full access.
           - dev-user
           - ci-deploy

  [FAIL]  HIGH  Access Keys Not Rotated (90+ Days)
         1 active key(s) are overdue for rotation.
           - dev-user (key AKIAIOSFOD..., 142d old)

  [WARN]  MEDIUM  Dual Access (Console + Programmatic)
         1 user(s) have both console and API access. Confirm this is intentional.
           - dev-user

PASSING
  [PASS]  AdministratorAccess Policy Attached
  [PASS]  Root Account Activity
  [PASS]  Password Policy

============================================================

Full JSON report saved to: output/report_2025-01-15_143022.json
```

---

## Project Structure

```
aws-iam-security-auditor/
├── config.py            # AWS client setup, loads .env credentials
├── main.py              # Entry point — runs all checks and outputs report
├── auditor/
│   ├── iam_checks.py    # One function per security check
│   └── report.py        # Terminal formatting and JSON export
├── sample_output/       # Example report for reference
├── .env.example         # Credential template (safe to commit)
├── .env                 # Real credentials (gitignored, never commit)
└── requirements.txt
```
