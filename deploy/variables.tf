variable "break_glass_user_ids" {
  description = "List of break-glass / emergency access account object IDs to exclude from all policies."
  type        = list(string)
}

variable "admin_group_id" {
  description = "Object ID of the group containing all admin/privileged role users."
  type        = string
  default     = ""
}

variable "blocked_countries" {
  description = "List of two-letter country codes to block sign-ins from (ISO 3166-1 alpha-2)."
  type        = list(string)
  default     = ["KP", "IR", "RU", "CN"]
}

variable "session_max_hours" {
  description = "Maximum sign-in frequency in hours before re-authentication is required."
  type        = number
  default     = 12
}

variable "policy_state" {
  description = "State for deployed policies. Use 'enabledForReportingButNotEnforced' to test before enforcing."
  type        = string
  default     = "enabledForReportingButNotEnforced"

  validation {
    condition     = contains(["enabled", "enabledForReportingButNotEnforced", "disabled"], var.policy_state)
    error_message = "policy_state must be 'enabled', 'enabledForReportingButNotEnforced', or 'disabled'."
  }
}
