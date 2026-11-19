variable "partner_org_id" {
  description = "Numeric Google Cloud Organization ID of the Partner owning the Billing Accounts."
  type        = string
}

variable "parent_billing_account_id" {
  description = "Partner parent Reseller Billing Account ID (e.g., 01ABCD-23EFGH-45IJKL)."
  type        = string
}

variable "broker_project_id" {
  description = "Project ID hosting the Billing Broker API, Portal UI, and Firestore (partner-billing-broker-prod)."
  type        = string
}

variable "linkers_project_id" {
  description = "Isolated Project ID hosting only per-tenant Linker Service Accounts (partner-billing-linkers-prod)."
  type        = string
}

variable "secops_project_id" {
  description = "Immutable SecOps Project ID hosting the Aggregated Audit Log Sink and Watchdog (partner-billing-secops-prod)."
  type        = string
}

variable "region" {
  description = "Primary GCP region for Cloud Run and Firestore."
  type        = string
  default     = "europe-west1"
}

variable "broker_container_image" {
  description = "Artifact Registry digest for the Billing Broker API service."
  type        = string
}

variable "watchdog_container_image" {
  description = "Artifact Registry digest for the Real-Time Security Watchdog service."
  type        = string
}

variable "watchdog_mode" {
  description = "Watchdog remediation mode: DRY_RUN (alert-only during Phase 1-3 backfill) or ENFORCE (<10s auto-unlink)."
  type        = string
  default     = "DRY_RUN"

  validation {
    condition     = contains(["DRY_RUN", "ENFORCE"], var.watchdog_mode)
    error_message = "watchdog_mode must be either DRY_RUN or ENFORCE."
  }
}

variable "tenants" {
  description = "Registry of customer tenants mapped 1:1 to Partner Billing Subaccounts."
  type = map(object({
    display_name                    = string
    billing_subaccount_id           = string
    allowed_org_ids                 = list(string)
    allowed_folder_ids              = optional(list(string), [])
    tier                            = optional(string, "ENTERPRISE_ORG") # ENTERPRISE_ORG | STANDARD_ORG
    max_links_per_hour              = optional(number, 5)
    default_project_budget_eur      = optional(number, 500)
    msa_auto_circuit_breaker_opt_in = optional(bool, false)
    security_contact_email          = string
  }))
}
