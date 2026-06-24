# main.tf
# Zero Trust Conditional Access policies for Microsoft Entra ID.
# Each policy maps to a baseline check in the audit engine.
#
# To deploy:
#   1. cp terraform.tfvars.example terraform.tfvars
#   2. Fill in your values (break-glass IDs, admin group ID)
#   3. terraform init
#   4. terraform plan    (review what will be created)
#   5. terraform apply   (deploy the policies)
#
# Policies deploy in report-only mode by default.
# Change policy_state to "enabled" in terraform.tfvars
# after verifying in sign-in logs.

# --- ZT-001: Block Legacy Authentication ---
# Blocks Exchange ActiveSync and other legacy auth clients.
# Legacy auth cannot do MFA, making it a primary attack vector.
# CIS M365 6.2.1

resource "azuread_conditional_access_policy" "block_legacy_auth" {
  display_name = "ZT-001: Block Legacy Authentication"
  state        = var.policy_state

  conditions {
    client_app_types = ["exchangeActiveSync", "other"]

    applications {
      included_applications = ["All"]
    }

    users {
      included_users = ["All"]
      excluded_users = var.break_glass_user_ids
    }
  }

  grant_controls {
    operator          = "OR"
    built_in_controls = ["block"]
  }
}

# --- ZT-002: Require MFA for Admins ---
# Requires MFA for the specified admin group.
# Admins are the highest-value targets in any tenant.
# CIS M365 6.2.2

resource "azuread_conditional_access_policy" "require_mfa_admins" {
  display_name = "ZT-002: Require MFA for Admins"
  state        = var.policy_state

  conditions {
    client_app_types = ["browser", "mobileAppsAndDesktopClients"]

    applications {
      included_applications = ["All"]
    }

    users {
      included_groups = [var.admin_group_id]
      excluded_users  = var.break_glass_user_ids
    }
  }

  grant_controls {
    operator          = "OR"
    built_in_controls = ["mfa"]
  }
}

# --- ZT-003: Require MFA for All Users ---
# Baseline MFA requirement for every user.
# CIS M365 6.2.3

resource "azuread_conditional_access_policy" "require_mfa_all_users" {
  display_name = "ZT-003: Require MFA for All Users"
  state        = var.policy_state

  conditions {
    client_app_types = ["browser", "mobileAppsAndDesktopClients"]

    applications {
      included_applications = ["All"]
    }

    users {
      included_users = ["All"]
      excluded_users = var.break_glass_user_ids
    }
  }

  grant_controls {
    operator          = "OR"
    built_in_controls = ["mfa"]
  }
}

# --- ZT-004: Require MFA for Risky Sign-ins ---
# Triggers MFA when Identity Protection detects medium or high
# sign-in risk (impossible travel, unfamiliar location, etc).
# CIS M365 6.2.4

resource "azuread_conditional_access_policy" "block_high_risk_signin" {
  display_name = "ZT-004: Require MFA for Risky Sign-ins"
  state        = var.policy_state

  conditions {
    client_app_types    = ["browser", "mobileAppsAndDesktopClients"]
    sign_in_risk_levels = ["medium", "high"]

    applications {
      included_applications = ["All"]
    }

    users {
      included_users = ["All"]
      excluded_users = var.break_glass_user_ids
    }
  }

  grant_controls {
    operator          = "OR"
    built_in_controls = ["mfa"]
  }
}

# --- ZT-005: Require Password Change for User Risk ---
# Forces password change + MFA when Identity Protection flags
# a user as high risk (leaked credentials, anomalous behavior).
# CIS M365 6.2.5

resource "azuread_conditional_access_policy" "require_password_change_user_risk" {
  display_name = "ZT-005: Require Password Change for User Risk"
  state        = var.policy_state

  conditions {
    client_app_types = ["all"]
    user_risk_levels = ["high"]

    applications {
      included_applications = ["All"]
    }

    users {
      included_users = ["All"]
      excluded_users = var.break_glass_user_ids
    }
  }

  grant_controls {
    operator          = "AND"
    built_in_controls = ["mfa", "passwordChange"]
  }
}

# --- ZT-006: Block High-Risk Country Sign-ins ---
# Blocks sign-ins from specified countries plus unknown locations.
# CIS M365 6.2.6

/*
resource "azuread_named_location" "blocked_countries" {
  display_name = "ZT - Blocked Countries"

  country {
    countries_and_regions                 = var.blocked_countries
    include_unknown_countries_and_regions = true
  }
}

resource "azuread_conditional_access_policy" "block_unknown_locations" {
  display_name = "ZT-006: Block High-Risk Country Sign-ins"
  state        = var.policy_state

  conditions {
    client_app_types = ["browser", "mobileAppsAndDesktopClients"]

    applications {
      included_applications = ["All"]
    }

    users {
      included_users = ["All"]
      excluded_users = var.break_glass_user_ids
    }

    locations {
      included_locations = [azuread_named_location.blocked_countries.id]
    }
  }

  grant_controls {
    operator          = "OR"
    built_in_controls = ["block"]
  }

  depends_on = [azuread_named_location.blocked_countries]
}
*/

# --- ZT-008: Enforce Session Sign-in Frequency ---
# Forces re-authentication after a set number of hours and
# disables persistent browser sessions.
# CIS M365 6.2.7

resource "azuread_conditional_access_policy" "session_frequency" {
  display_name = "ZT-008: Enforce Session Sign-in Frequency"
  state        = var.policy_state

  conditions {
    client_app_types = ["browser", "mobileAppsAndDesktopClients"]

    applications {
      included_applications = ["All"]
    }

    users {
      included_users = ["All"]
      excluded_users = var.break_glass_user_ids
    }
  }

  grant_controls {
    operator          = "OR"
    built_in_controls = ["mfa"]
  }

  session_controls {
    sign_in_frequency                 = var.session_max_hours
    sign_in_frequency_period          = "hours"
    persistent_browser_mode           = "never"
  }
}

