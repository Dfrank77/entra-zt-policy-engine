# Entra ID Zero Trust Policy Audit Report

**Generated:** 2026-06-24 11:15 UTC
**Policies evaluated:** 9
**Named locations:** 1

---

## Summary

| Result | Count |
|--------|-------|
| PASS | 9 |
| FAIL | 0 |
| WARNING | 1 |

---

## Warnings

### ZT-009: Report-only policies

**Status:** WARNING

7 policy/policies in report-only mode: ZT-008: Enforce Session Sign-in Frequency, ZT-001: Block Legacy Authentication, ZT-004: Require MFA for Risky Sign-ins, ZT-002: Require MFA for Admins, ZT-003: Require MFA for All Users, ZT-005: Require Password Change for User Risk, ZT-006: Block High-Risk Country Sign-ins. Review and enable when ready.

**Reference:** MS CA best practices

---

## Passed

### ZT-001: Block legacy authentication

**Status:** PASS

Policy 'ZT-001: Block Legacy Authentication' blocks legacy auth clients.

**Reference:** CIS M365 5.2.2.3 / MS Zero Trust CA guidance

### ZT-002: Require MFA for admin roles

**Status:** PASS

Policy 'ZT-002: Require MFA for Admins' requires MFA for admin roles or admin groups.

**Reference:** CIS M365 5.2.2.1 / MS Zero Trust CA guidance

### ZT-003: Require MFA for all users

**Status:** PASS

Policy 'ZT-008: Enforce Session Sign-in Frequency' requires MFA for all users.

**Reference:** CIS M365 5.2.2.2 / MS Zero Trust CA guidance

### ZT-004: Sign-in risk policy configured

**Status:** PASS

Policy 'ZT-004: Require MFA for Risky Sign-ins' enforces MFA on risky sign-ins.

**Reference:** CIS M365 5.2.2.6 / MS Identity Protection guidance

### ZT-005: User risk policy configured

**Status:** PASS

Policy 'ZT-005: Require Password Change for User Risk' responds to user risk.

**Reference:** CIS M365 5.2.2.7 / MS Identity Protection guidance

### ZT-006: Location-based access controls

**Status:** PASS

Policy 'ZT-006: Block High-Risk Country Sign-ins' uses location conditions. 1 named location(s) defined.

**Reference:** CIS M365 5.2.2.8 / MS Zero Trust CA guidance

### ZT-007: Break-glass account exclusions

**Status:** PASS

All policies targeting 'All users' have user or group exclusions.

**Reference:** MS Emergency Access Accounts guidance

### ZT-008: Session controls configured

**Status:** PASS

Policy 'ZT-008: Enforce Session Sign-in Frequency' has session controls (sign-in frequency or persistent browser).

**Reference:** CIS M365 5.2.2.4 / MS Zero Trust CA guidance

### ZT-010: Disabled policies

**Status:** PASS

No disabled policies found.

**Reference:** MS CA best practices
