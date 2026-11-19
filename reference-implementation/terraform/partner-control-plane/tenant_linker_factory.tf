# Orchestrator Service Account running the Broker Cloud Run API (Zero static keys)
resource "google_service_account" "broker_orchestrator" {
  project      = var.broker_project_id
  account_id   = "sa-broker-orchestrator"
  display_name = "Billing Broker Control Plane Orchestrator"

  depends_on = [google_project_service.platform_apis]
}

# 1:1 Tenant-Isolated Linker Service Accounts (Strictly 1 SA per Customer Subaccount)
resource "google_service_account" "tenant_linker" {
  for_each = var.tenants

  project      = var.linkers_project_id
  account_id   = "sa-linker-${substr(replace(lower(each.key), "_", "-"), 0, 18)}"
  display_name = "Billing Linker SA - ${each.value.display_name}"
  description  = "Isolated 1:1 Linker SA for subaccount ${each.value.billing_subaccount_id}"

  depends_on = [google_project_service.platform_apis]
}

# Allow Broker Orchestrator to mint short-lived (10m) OAuth2 tokens for each Tenant SA
resource "google_service_account_iam_member" "orchestrator_impersonation" {
  for_each = google_service_account.tenant_linker

  service_account_id = each.value.name
  role               = "roles/iam.serviceAccountTokenCreator"
  member             = "serviceAccount:${google_service_account.broker_orchestrator.email}"
}

# Bind each Tenant Linker SA ONLY to its single mapped Customer Billing Subaccount
resource "google_billing_account_iam_member" "tenant_subaccount_linker_binding" {
  for_each = var.tenants

  billing_account_id = each.value.billing_subaccount_id
  role               = google_organization_iam_custom_role.subaccount_linker.name
  member             = "serviceAccount:${google_service_account.tenant_linker[each.key].email}"
}

# Seed Tenant Policy Metadata directly into Firestore Native Registry
resource "google_firestore_document" "tenant_policy" {
  for_each = var.tenants

  project     = var.broker_project_id
  database    = google_firestore_database.broker_db.name
  collection  = "tenants"
  document_id = each.key

  fields = jsonencode({
    display_name                    = { stringValue = each.value.display_name }
    billing_subaccount_id           = { stringValue = each.value.billing_subaccount_id }
    linker_sa_email                 = { stringValue = google_service_account.tenant_linker[each.key].email }
    tier                            = { stringValue = each.value.tier }
    max_links_per_hour              = { integerValue = tostring(each.value.max_links_per_hour) }
    default_project_budget_eur      = { integerValue = tostring(each.value.default_project_budget_eur) }
    msa_auto_circuit_breaker_opt_in = { booleanValue = each.value.msa_auto_circuit_breaker_opt_in }
    security_contact_email          = { stringValue = each.value.security_contact_email }
    status                          = { stringValue = "ACTIVE" }
    allowed_org_ids = {
      arrayValue = {
        values = [for org_id in each.value.allowed_org_ids : { stringValue = org_id }]
      }
    }
    allowed_folder_ids = {
      arrayValue = {
        values = [for folder_id in each.value.allowed_folder_ids : { stringValue = folder_id }]
      }
    }
  })
}
