# Least-Privilege Custom Role for Per-Tenant Linker Service Accounts.
# Intentionally OMITS billing.resourceAssociations.delete and billing.accounts.setIamPolicy
# so a Linker SA can never detach production workloads or alter Billing IAM.
resource "google_organization_iam_custom_role" "subaccount_linker" {
  org_id      = var.partner_org_id
  role_id     = "partnerSubaccountLinker"
  title       = "Partner Subaccount Project Linker"
  description = "Attaches validated projects and creates baseline budgets on a single Billing Subaccount."

  permissions = [
    "billing.accounts.get",
    "billing.resourceAssociations.create",
    "billing.resourceAssociations.list",
    "billing.budgets.create",
    "billing.budgets.get",
    "billing.budgets.list",
  ]
}

# Least-Privilege Custom Role for the isolated Real-Time Security Watchdog.
# Grants emergency project unlink and IAM audit visibility without full billing.admin privileges.
resource "google_organization_iam_custom_role" "billing_watchdog" {
  org_id      = var.partner_org_id
  role_id     = "partnerBillingWatchdog"
  title       = "Partner Security Billing Watchdog"
  description = "Detects and detaches unauthorized external project links in <10s."

  permissions = [
    "billing.accounts.get",
    "billing.accounts.getIamPolicy",
    "billing.resourceAssociations.list",
    "billing.resourceAssociations.delete",
  ]
}
