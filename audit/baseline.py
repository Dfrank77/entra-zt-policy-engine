"""
baseline.py
Evaluates Conditional Access policies against a Zero Trust baseline
derived from CIS Microsoft 365 Foundations Benchmark and Microsoft's
Conditional Access for Zero Trust guidance.

Each check returns a dict with:
  - id: check identifier
  - name: short description
  - status: PASS, FAIL, or WARNING
  - detail: explanation of the finding
  - reference: CIS control or Microsoft doc reference
"""


def _policies_by_state(policies, state):
    """Filter policies that are enabled or report-only (active)."""
    if state == "active":
        return [
            p for p in policies
            if p.get("state") in ("enabled", "enabledForReportingButNotEnforced")
        ]
    return [p for p in policies if p.get("state") == state]


def _policy_targets_all_users(policy):
    """Check if a policy includes all users."""
    users = policy.get("conditions", {}).get("users", {})
    include = users.get("includeUsers", [])
    return "All" in include


def _policy_targets_admin_roles(policy):
    """Check if a policy includes directory roles (admin roles)."""
    users = policy.get("conditions", {}).get("users", {})
    roles = users.get("includeRoles", [])
    return len(roles) > 0


def _policy_targets_admin_groups(policy):
    """Check if a policy includes specific groups (admin groups)."""
    users = policy.get("conditions", {}).get("users", {})
    groups = users.get("includeGroups", [])
    return len(groups) > 0


def _policy_requires_mfa(policy):
    """Check if a policy requires MFA in grant controls."""
    grant = policy.get("grantControls", {})
    if grant is None:
        return False
    built_in = grant.get("builtInControls", [])
    return "mfa" in built_in


def _policy_blocks_access(policy):
    """Check if a policy blocks access."""
    grant = policy.get("grantControls", {})
    if grant is None:
        return False
    built_in = grant.get("builtInControls", [])
    return "block" in built_in


def _policy_blocks_legacy_auth(policy):
    """Check if a policy blocks legacy authentication clients."""
    conditions = policy.get("conditions", {})
    client_app_types = conditions.get("clientAppTypes", [])
    legacy_types = {"exchangeActiveSync", "other"}
    targets_legacy = legacy_types.intersection(set(client_app_types))
    return len(targets_legacy) > 0 and _policy_blocks_access(policy)


def _policy_has_break_glass_exclusion(policy):
    """Check if a policy excludes any users or groups (potential break-glass)."""
    users = policy.get("conditions", {}).get("users", {})
    excluded_users = users.get("excludeUsers", [])
    excluded_groups = users.get("excludeGroups", [])
    return len(excluded_users) > 0 or len(excluded_groups) > 0


def _policy_targets_signin_risk(policy):
    """Check if a policy conditions on sign-in risk level."""
    conditions = policy.get("conditions", {})
    risk_levels = conditions.get("signInRiskLevels", [])
    return len(risk_levels) > 0


def _policy_targets_user_risk(policy):
    """Check if a policy conditions on user risk level."""
    conditions = policy.get("conditions", {})
    risk_levels = conditions.get("userRiskLevels", [])
    return len(risk_levels) > 0


def _policy_has_session_controls(policy):
    """Check if a policy sets session frequency or persistent browser."""
    session = policy.get("sessionControls", {})
    if session is None:
        return False
    sign_in_freq = session.get("signInFrequency", {})
    persistent_browser = session.get("persistentBrowser", {})
    has_freq = sign_in_freq is not None and sign_in_freq.get("isEnabled", False)
    has_browser = persistent_browser is not None and persistent_browser.get("isEnabled", False)
    return has_freq or has_browser


def check_legacy_auth_blocked(policies):
    """ZT-001: Legacy authentication must be blocked."""
    active = _policies_by_state(policies, "active")
    for p in active:
        conditions = p.get("conditions", {})
        client_app_types = conditions.get("clientAppTypes", [])
        if "other" in client_app_types and _policy_blocks_access(p):
            return {
                "id": "ZT-001",
                "name": "Block legacy authentication",
                "status": "PASS",
                "detail": f"Policy '{p.get('displayName')}' blocks legacy auth clients.",
                "reference": "CIS M365 5.2.2.3 / MS Zero Trust CA guidance",
            }
    return {
        "id": "ZT-001",
        "name": "Block legacy authentication",
        "status": "FAIL",
        "detail": "No active policy blocks legacy authentication (clientAppTypes: 'other').",
        "reference": "CIS M365 5.2.2.3 / MS Zero Trust CA guidance",
    }


def check_mfa_admins(policies):
    """ZT-002: MFA required for all admin roles."""
    active = _policies_by_state(policies, "active")
    for p in active:
        if (_policy_targets_admin_roles(p) or _policy_targets_admin_groups(p)) and _policy_requires_mfa(p):
            return {
                "id": "ZT-002",
                "name": "Require MFA for admin roles",
                "status": "PASS",
                "detail": f"Policy '{p.get('displayName')}' requires MFA for admin roles or admin groups.",
                "reference": "CIS M365 5.2.2.1 / MS Zero Trust CA guidance",
            }
    return {
        "id": "ZT-002",
        "name": "Require MFA for admin roles",
        "status": "FAIL",
        "detail": "No active policy requires MFA for directory roles or admin groups.",
        "reference": "CIS M365 5.2.2.1 / MS Zero Trust CA guidance",
    }


def check_mfa_all_users(policies):
    """ZT-003: MFA required for all users."""
    active = _policies_by_state(policies, "active")
    for p in active:
        if _policy_targets_all_users(p) and _policy_requires_mfa(p):
            return {
                "id": "ZT-003",
                "name": "Require MFA for all users",
                "status": "PASS",
                "detail": f"Policy '{p.get('displayName')}' requires MFA for all users.",
                "reference": "CIS M365 5.2.2.2 / MS Zero Trust CA guidance",
            }
    return {
        "id": "ZT-003",
        "name": "Require MFA for all users",
        "status": "FAIL",
        "detail": "No active policy requires MFA for all users.",
        "reference": "CIS M365 5.2.2.2 / MS Zero Trust CA guidance",
    }


def check_signin_risk_policy(policies):
    """ZT-004: Sign-in risk policy must be configured."""
    active = _policies_by_state(policies, "active")
    for p in active:
        if _policy_targets_signin_risk(p) and _policy_requires_mfa(p):
            return {
                "id": "ZT-004",
                "name": "Sign-in risk policy configured",
                "status": "PASS",
                "detail": f"Policy '{p.get('displayName')}' enforces MFA on risky sign-ins.",
                "reference": "CIS M365 5.2.2.6 / MS Identity Protection guidance",
            }
    return {
        "id": "ZT-004",
        "name": "Sign-in risk policy configured",
        "status": "FAIL",
        "detail": "No active policy requires MFA based on sign-in risk level.",
        "reference": "CIS M365 5.2.2.6 / MS Identity Protection guidance",
    }


def check_user_risk_policy(policies):
    """ZT-005: User risk policy must be configured."""
    active = _policies_by_state(policies, "active")
    for p in active:
        if _policy_targets_user_risk(p):
            grant = p.get("grantControls", {})
            if grant is None:
                continue
            built_in = grant.get("builtInControls", [])
            if "passwordChange" in built_in or "mfa" in built_in:
                return {
                    "id": "ZT-005",
                    "name": "User risk policy configured",
                    "status": "PASS",
                    "detail": f"Policy '{p.get('displayName')}' responds to user risk.",
                    "reference": "CIS M365 5.2.2.7 / MS Identity Protection guidance",
                }
    return {
        "id": "ZT-005",
        "name": "User risk policy configured",
        "status": "FAIL",
        "detail": "No active policy requires password change or MFA based on user risk level.",
        "reference": "CIS M365 5.2.2.7 / MS Identity Protection guidance",
    }


def check_location_based_policy(policies, named_locations):
    """ZT-006: Location-based access controls must be configured."""
    if len(named_locations) == 0:
        return {
            "id": "ZT-006",
            "name": "Location-based access controls",
            "status": "FAIL",
            "detail": "No named locations defined. Cannot enforce location-based policies.",
            "reference": "CIS M365 5.2.2.8 / MS Zero Trust CA guidance",
        }
    active = _policies_by_state(policies, "active")
    for p in active:
        conditions = p.get("conditions", {})
        locations = conditions.get("locations", {})
        if locations and (locations.get("includeLocations") or locations.get("excludeLocations")):
            return {
                "id": "ZT-006",
                "name": "Location-based access controls",
                "status": "PASS",
                "detail": f"Policy '{p.get('displayName')}' uses location conditions. {len(named_locations)} named location(s) defined.",
                "reference": "CIS M365 5.2.2.8 / MS Zero Trust CA guidance",
            }
    return {
        "id": "ZT-006",
        "name": "Location-based access controls",
        "status": "WARNING",
        "detail": f"{len(named_locations)} named location(s) defined but no active policy uses location conditions.",
        "reference": "CIS M365 5.2.2.8 / MS Zero Trust CA guidance",
    }


def check_break_glass_exclusions(policies):
    """ZT-007: Policies targeting all users must exclude break-glass accounts."""
    active = _policies_by_state(policies, "active")
    issues = []
    for p in active:
        if _policy_targets_all_users(p) and not _policy_has_break_glass_exclusion(p):
            issues.append(p.get("displayName", "Unnamed"))
    if not issues:
        return {
            "id": "ZT-007",
            "name": "Break-glass account exclusions",
            "status": "PASS",
            "detail": "All policies targeting 'All users' have user or group exclusions.",
            "reference": "MS Emergency Access Accounts guidance",
        }
    return {
        "id": "ZT-007",
        "name": "Break-glass account exclusions",
        "status": "WARNING",
        "detail": f"Policies without break-glass exclusions: {', '.join(issues)}",
        "reference": "MS Emergency Access Accounts guidance",
    }


def check_session_controls(policies):
    """ZT-008: Session controls should be configured."""
    active = _policies_by_state(policies, "active")
    for p in active:
        if _policy_has_session_controls(p):
            return {
                "id": "ZT-008",
                "name": "Session controls configured",
                "status": "PASS",
                "detail": f"Policy '{p.get('displayName')}' has session controls (sign-in frequency or persistent browser).",
                "reference": "CIS M365 5.2.2.4 / MS Zero Trust CA guidance",
            }
    return {
        "id": "ZT-008",
        "name": "Session controls configured",
        "status": "FAIL",
        "detail": "No active policy configures session sign-in frequency or persistent browser settings.",
        "reference": "CIS M365 5.2.2.4 / MS Zero Trust CA guidance",
    }


def check_report_only_policies(policies):
    """ZT-009: Flag policies stuck in report-only mode."""
    report_only = [
        p.get("displayName", "Unnamed")
        for p in policies
        if p.get("state") == "enabledForReportingButNotEnforced"
    ]
    if not report_only:
        return {
            "id": "ZT-009",
            "name": "Report-only policies",
            "status": "PASS",
            "detail": "No policies are in report-only mode.",
            "reference": "MS CA best practices",
        }
    return {
        "id": "ZT-009",
        "name": "Report-only policies",
        "status": "WARNING",
        "detail": f"{len(report_only)} policy/policies in report-only mode: {', '.join(report_only)}. Review and enable when ready.",
        "reference": "MS CA best practices",
    }


def check_disabled_policies(policies):
    """ZT-010: Flag disabled policies that may indicate incomplete deployment."""
    disabled = [
        p.get("displayName", "Unnamed")
        for p in policies
        if p.get("state") == "disabled"
    ]
    if not disabled:
        return {
            "id": "ZT-010",
            "name": "Disabled policies",
            "status": "PASS",
            "detail": "No disabled policies found.",
            "reference": "MS CA best practices",
        }
    return {
        "id": "ZT-010",
        "name": "Disabled policies",
        "status": "WARNING",
        "detail": f"{len(disabled)} disabled policy/policies: {', '.join(disabled)}. Consider enabling or removing.",
        "reference": "MS CA best practices",
    }


def run_all_checks(policies, named_locations):
    """Run all baseline checks and return results."""
    results = [
        check_legacy_auth_blocked(policies),
        check_mfa_admins(policies),
        check_mfa_all_users(policies),
        check_signin_risk_policy(policies),
        check_user_risk_policy(policies),
        check_location_based_policy(policies, named_locations),
        check_break_glass_exclusions(policies),
        check_session_controls(policies),
        check_report_only_policies(policies),
        check_disabled_policies(policies),
    ]
    return results