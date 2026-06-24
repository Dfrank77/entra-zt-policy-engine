# entra-zt-policy-engine

Zero Trust Conditional Access policy engine for Microsoft Entra ID. Audits an existing tenant against CIS Microsoft 365 Foundations Benchmark and Microsoft Zero Trust guidance, then deploys gap-closing policies via Terraform.

## What This Does

Most CA-as-code repos deploy policies. This one audits first.

The **audit engine** (Python) connects to a live Entra ID tenant via Microsoft Graph, pulls all Conditional Access policies and named locations, and evaluates them against 10 Zero Trust baseline checks. It generates a markdown gap report showing what's passing, what's failing, and what needs attention.

The **deploy engine** (Terraform) provides a complete set of Zero Trust CA policies mapped to the same baseline checks. Policies deploy in report-only mode by default so you can verify behavior in sign-in logs before enforcing.

## Baseline Checks

| ID | Check | Reference |
|----|-------|-----------|
| ZT-001 | Block legacy authentication | CIS M365 5.2.2.3 |
| ZT-002 | Require MFA for admin roles | CIS M365 5.2.2.1 |
| ZT-003 | Require MFA for all users | CIS M365 5.2.2.2 |
| ZT-004 | Sign-in risk policy configured | CIS M365 5.2.2.6 |
| ZT-005 | User risk policy configured | CIS M365 5.2.2.7 |
| ZT-006 | Location-based access controls | CIS M365 5.2.2.8 |
| ZT-007 | Break-glass account exclusions | MS Emergency Access guidance |
| ZT-008 | Session controls configured | CIS M365 5.2.2.4 |
| ZT-009 | Report-only policies flagged | MS CA best practices |
| ZT-010 | Disabled policies flagged | MS CA best practices |

## Sample Output

### Before: Initial Audit

| Status | Check |
|--------|-------|
| ✅ Pass | ZT-001: Block legacy authentication |
| ❌ Fail | ZT-002: Require MFA for admin roles |
| ✅ Pass | ZT-003: Require MFA for all users |
| ✅ Pass | ZT-004: Sign-in risk policy configured |
| ✅ Pass | ZT-005: User risk policy configured |
| ⚠️ Warn | ZT-006: Location-based access controls |
| ✅ Pass | ZT-007: Break-glass account exclusions |
| ❌ Fail | ZT-008: Session controls configured |
| ⚠️ Warn | ZT-009: Report-only policies |
| ⚠️ Warn | ZT-010: Disabled policies |

**Results: 5 passed, 2 failed, 3 warnings**

### After: Post-Deployment Audit

| Status | Check |
|--------|-------|
| ✅ Pass | ZT-001: Block legacy authentication |
| ✅ Pass | ZT-002: Require MFA for admin roles |
| ✅ Pass | ZT-003: Require MFA for all users |
| ✅ Pass | ZT-004: Sign-in risk policy configured |
| ✅ Pass | ZT-005: User risk policy configured |
| ✅ Pass | ZT-006: Location-based access controls |
| ✅ Pass | ZT-007: Break-glass account exclusions |
| ✅ Pass | ZT-008: Session controls configured |
| ⚠️ Warn | ZT-009: Report-only policies |
| ✅ Pass | ZT-010: Disabled policies |

**Results: 9 passed, 0 failed, 1 warning**

Full reports available at [sample-output/before_report.md](sample-output/before_report.md) and [sample-output/after_report.md](sample-output/after_report.md).

## Project Structure

```
entra-zt-policy-engine/
├── audit/
│   ├── audit.py              # main entry point
│   ├── graph_client.py       # Graph API auth + data pull
│   ├── baseline.py           # zero trust baseline checks
│   ├── report.py             # markdown report generator
│   └── requirements.txt      # Python dependencies
├── deploy/
│   ├── providers.tf          # AzureAD provider config
│   ├── variables.tf          # input variables
│   ├── main.tf               # all CA policy resources
│   ├── outputs.tf            # deployment outputs
│   └── terraform.tfvars.example  # template for user config
├── sample-output/
│   ├── before_report.md      # audit before deployment
│   ├── after_report.md       # audit after deployment
│   └── gap_report.md         # latest audit report
└── README.md
```

## Prerequisites

- Python 3.9+
- Terraform 1.5+
- Azure CLI (`az login`)
- An Entra ID tenant with P1 or P2 licensing (required for Conditional Access)
- Account with Security Reader role (audit) or Conditional Access Administrator role (deploy)

## Usage

### Audit

Run the audit to see your tenant's current Zero Trust posture:

```bash
# Clone the repo
git clone https://github.com/Dfrank77/entra-zt-policy-engine.git
cd entra-zt-policy-engine

# Set up Python environment
python3 -m venv venv
source venv/bin/activate
pip install -r audit/requirements.txt

# Authenticate to your tenant
az login

# Run the audit
cd audit
python audit.py
```

The audit generates a gap report at `sample-output/gap_report.md`.

### Deploy

Close the gaps identified by the audit:

```bash
cd deploy

# Configure your environment
cp terraform.tfvars.example terraform.tfvars
# Edit terraform.tfvars with your break-glass IDs, admin group ID, etc.

# Deploy
terraform init
terraform plan
terraform apply
```

Policies deploy in **report-only mode** by default. Monitor sign-in logs to verify behavior, then change `policy_state` to `"enabled"` in `terraform.tfvars` and run `terraform apply` again.

### Re-audit

After deploying, run the audit again to confirm the gaps are closed:

```bash
cd ../audit
python audit.py
```

## Deployed Policies

| ID | Policy | What It Does |
|----|--------|-------------|
| ZT-001 | Block Legacy Authentication | Blocks Exchange ActiveSync and other legacy auth clients that cannot perform MFA |
| ZT-002 | Require MFA for Admins | Requires MFA for the specified admin group |
| ZT-003 | Require MFA for All Users | Baseline MFA requirement for every user in the tenant |
| ZT-004 | Require MFA for Risky Sign-ins | Triggers MFA on medium and high risk sign-ins detected by Identity Protection |
| ZT-005 | Require Password Change for User Risk | Forces password change and MFA when a user account is flagged as high risk |
| ZT-006 | Block High-Risk Country Sign-ins | Blocks sign-ins from specified countries and unknown locations |
| ZT-008 | Enforce Session Sign-in Frequency | Forces re-authentication after a configurable number of hours and disables persistent browser sessions |

All policies exclude break-glass accounts to prevent tenant lockout.

## References

- [CIS Microsoft 365 Foundations Benchmark](https://www.cisecurity.org/benchmark/microsoft_365)
- [Microsoft Zero Trust Conditional Access guidance](https://learn.microsoft.com/en-us/entra/identity/conditional-access/plan-conditional-access)
- [Microsoft Emergency Access Accounts](https://learn.microsoft.com/en-us/entra/identity/role-based-access-control/security-emergency-access)
- [AzureAD Terraform Provider](https://registry.terraform.io/providers/hashicorp/azuread/latest/docs)

## License

MIT