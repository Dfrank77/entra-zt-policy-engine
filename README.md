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

