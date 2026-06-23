output "deployed_policies" {
  description = "List of deployed Zero Trust CA policy names and their states."
  value = {
    "ZT-001" = azuread_conditional_access_policy.block_legacy_auth.display_name
    "ZT-002" = azuread_conditional_access_policy.require_mfa_admins.display_name
    "ZT-003" = azuread_conditional_access_policy.require_mfa_all_users.display_name
    "ZT-004" = azuread_conditional_access_policy.block_high_risk_signin.display_name
    "ZT-005" = azuread_conditional_access_policy.require_password_change_user_risk.display_name
    "ZT-006" = azuread_conditional_access_policy.block_unknown_locations.display_name
    "ZT-008" = azuread_conditional_access_policy.session_frequency.display_name
  }
}

output "policy_state" {
  description = "Current deployment state of all policies."
  value       = var.policy_state
}
