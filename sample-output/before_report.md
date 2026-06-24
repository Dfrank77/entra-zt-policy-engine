# Entra ID Zero Trust Policy Audit Report

**Generated:** 2026-06-23 13:54 UTC
**Policies evaluated:** 12
**Named locations:** 1

---

## Summary

| Result | Count |
|--------|-------|
| PASS | 5 |
| FAIL | 2 |
| WARNING | 3 |

---

## Failures

### ZT-002: Require MFA for admin roles

**Status:** FAIL

No active policy requires MFA for directory roles.

**Reference:** CIS M365 6.2.2 / MS Zero Trust CA guidance

### ZT-008: Session controls configured

**Status:** FAIL

No active policy configures session sign-in frequency or persistent browser settings.

**Reference:** CIS M365 6.2.7 / MS Zero Trust CA guidance

---

## Warnings

### ZT-006: Location-based access controls

**Status:** WARNING

1 named location(s) defined but no active policy uses location conditions.

**Reference:** CIS M365 6.2.6 / MS Zero Trust CA guidance

### ZT-009: Report-only policies

**Status:** WARNING

7 policy/policies in report-only mode: CA001 - Require MFA - Admins, CA002 - Require MFA - All Users, CA003 - Block Legacy Authentication, CA004 - Require MFA - Risky Sign-ins, CA005 - Require MFA - Azure Management, Terms of Use, CA006 - User Risk-Require Password Change. Review and enable when ready.

**Reference:** MS CA best practices

### ZT-010: Disabled policies

**Status:** WARNING

3 disabled policy/policies: IaC - Require MFA for Admin Roles, IaC - Block Legacy Authentication, IaC - Block Sign-Ins from High-Risk Countries. Consider enabling or removing.

**Reference:** MS CA best practices

---

## Passed

### ZT-001: Block legacy authentication

**Status:** PASS

Policy 'CA003 - Block Legacy Authentication' blocks legacy auth clients.

**Reference:** CIS M365 6.2.1 / MS Zero Trust CA guidance

### ZT-003: Require MFA for all users

**Status:** PASS

Policy 'CA002 - Require MFA - All Users' requires MFA for all users.

**Reference:** CIS M365 6.2.3 / MS Zero Trust CA guidance

### ZT-004: Sign-in risk policy configured

**Status:** PASS

Policy 'CA004 - Require MFA - Risky Sign-ins' enforces MFA on risky sign-ins.

**Reference:** CIS M365 6.2.4 / MS Identity Protection guidance

### ZT-005: User risk policy configured

**Status:** PASS

Policy 'CA006 - User Risk-Require Password Change' responds to user risk.

**Reference:** CIS M365 6.2.5 / MS Identity Protection guidance

### ZT-007: Break-glass account exclusions

**Status:** PASS

All policies targeting 'All users' have user or group exclusions.

**Reference:** MS Emergency Access Accounts guidance
